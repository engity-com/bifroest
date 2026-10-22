package service

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type associationActor struct {
	authorization.Authorization
	identity authentication.Identity
	flow     configuration.FlowName
}

func (this associationActor) IsAuthorized() bool { return true }
func (this associationActor) Authentication() (authentication.Identity, error) {
	return this.identity, nil
}
func (this associationActor) Flow() configuration.FlowName { return this.flow }
func (associationActor) FindSession() session.Session      { return nil }

type associationAdapterConnection struct {
	bconn.Connection
	remote bnet.Remote
}

type associationAdapterRemote string

func (this associationAdapterRemote) User() string   { return string(this) }
func (associationAdapterRemote) Host() bnet.Host     { return bnet.MustNewHost("127.0.0.1") }
func (this associationAdapterRemote) String() string { return this.User() + "@" + this.Host().String() }
func (this associationAdapterRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return this.User(), true, nil
	case "host":
		return this.Host(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown adapter remote field")
	}
}

func (this associationAdapterConnection) Remote() bnet.Remote { return this.remote }

type associationAdapterContext struct {
	ctx       context.Context
	auth      authorization.Authorization
	remote    bnet.Remote
	selection bconn.Selection
}

func (this associationAdapterContext) Context() context.Context { return this.ctx }
func (this associationAdapterContext) Connection() bconn.Connection {
	return associationAdapterConnection{remote: this.remote}
}
func (this associationAdapterContext) Authorization() authorization.Authorization { return this.auth }
func (this associationAdapterContext) Selection() bconn.Selection                 { return this.selection }
func (this associationAdapterContext) GetField(name string) (any, bool, error) {
	switch name {
	case "authentication":
		identity, err := authorization.AuthenticationOf(this.auth)
		return identity, true, err
	case "remote":
		return this.remote, true, nil
	default:
		return nil, false, fmt.Errorf("unavailable adapter template field")
	}
}

func newAssociatedService(t *testing.T) (*service, *configuration.SessionFs) {
	t.Helper()
	conf := &configuration.SessionFs{}
	require.NoError(t, conf.SetDefaults())
	conf.Storage = t.TempDir()
	repository, err := session.NewFacadeRepository(t.Context(), &configuration.Session{V: conf})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	sshConf := &configuration.EnvironmentSsh{}
	require.NoError(t, sshConf.SetDefaults())
	sshConf.Address = template.MustNewString("{{ if .remote.user }}{{ .remote.user }}{{ else }}hostA{{ end }}")
	sshConf.User = template.MustNewString("account")
	sshConf.AcceptAllHostKeys = true // Only the pure resolver is used; no target connection.
	sshConf.IdentityFiles = template.MustNewStrings("/must/not/load/for/selection")
	environments, err := environment.NewSshRepository(t.Context(), "work", sshConf, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environments.Close()) })
	return &service{sessions: repository, environments: environments}, conf
}

func associationAdapter(t *testing.T, name string, transport bconn.Transport) associationAdapterContext {
	t.Helper()
	return associationAdapterContext{ctx: t.Context(), auth: associationActor{flow: "work", identity: authentication.Identity{Principal: "alice", Issuer: "test-authority", Subject: "stable-alice"}}, remote: associationAdapterRemote(name), selection: bconn.Selection{Transport: transport}}
}

func TestAssociationSelectionSharesNeutralAdaptersAndSurvivesRestart(t *testing.T) {
	svc, conf := newAssociatedService(t)
	ssh := associationAdapter(t, "hostA", bconn.TransportSsh)
	first, handled, err := svc.resolveAuthenticatedSession(ssh, []byte("static-credentials"))
	require.NoError(t, err)
	require.True(t, handled)
	http := associationAdapter(t, "", bconn.TransportHttp)
	http.selection.Host = "web.example"
	http.selection.Slug = "work"
	second, handled, err := svc.resolveAuthenticatedSession(http, []byte("static-credentials"))
	require.NoError(t, err)
	require.True(t, handled)
	require.Equal(t, first.Id(), second.Id())
	stored, err := second.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, "static-credentials", string(stored))
	other, _, err := svc.resolveAuthenticatedSession(associationAdapter(t, "hostB", bconn.TransportHttp), []byte("static-credentials"))
	require.NoError(t, err)
	require.NotEqual(t, first.Id(), other.Id())
	require.NoError(t, svc.sessions.Close())
	restarted, err := session.NewFacadeRepository(t.Context(), &configuration.Session{V: conf})
	require.NoError(t, err)
	defer restarted.Close()
	svc.sessions = restarted
	third, _, err := svc.resolveAuthenticatedSession(http, []byte("static-credentials"))
	require.NoError(t, err)
	require.Equal(t, first.Id(), third.Id())
}

func TestAssociationSelectionConcurrentAdaptersLegacyAndRevokedCredentials(t *testing.T) {
	svc, _ := newAssociatedService(t)
	base := associationAdapter(t, "hostA", bconn.TransportSsh)
	legacy, err := svc.sessions.Create(t.Context(), "work", base.remote, []byte("static"))
	require.NoError(t, err)
	const amount = 20
	results := make(chan session.Id, amount)
	failures := make(chan error, amount)
	var wait sync.WaitGroup
	for i := 0; i < amount; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			found, _, err := svc.resolveAuthenticatedSession(base, []byte("static"))
			if err != nil {
				failures <- err
				return
			}
			results <- found.Id()
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}
	var expected session.Id
	for id := range results {
		if expected.IsZero() {
			expected = id
		}
		require.Equal(t, expected, id)
		require.NotEqual(t, legacy.Id(), id)
	}
	old, err := session.AssociationOf(t.Context(), legacy)
	require.NoError(t, err)
	require.Nil(t, old)
	selected, err := svc.sessions.FindBy(t.Context(), "work", expected, nil)
	require.NoError(t, err)
	require.NoError(t, selected.SetAuthorizationToken(t.Context(), nil))
	replacement, _, err := svc.resolveAuthenticatedSession(base, []byte("static"))
	require.NoError(t, err)
	require.NotEqual(t, expected, replacement.Id())
	stored, err := selected.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Empty(t, stored, "fresh login must not overwrite revoked credentials")
}

func TestAssociationTargetContextUsesCandidateWithoutInventingMetadata(t *testing.T) {
	base := associationAdapter(t, "hostA", bconn.TransportSsh)
	ref := session.Reference{Flow: "work", Id: session.MustNewId()}
	ctx := newAssociationTargetContext(t.Context(), base, ref)
	value, err := template.MustNewString("{{.session.id}}|{{.authorization.session.id}}|{{.session.flow}}").Render(ctx)
	require.NoError(t, err)
	require.Equal(t, ref.Id.String()+"|"+ref.Id.String()+"|work", value)
	_, err = template.MustNewString("{{.session.created.at}}").Render(ctx)
	require.Error(t, err)
	request := &publicKeyAuthorizeRequest{}
	_, handled, err := request.ResolveAuthenticatedSession(base.auth, []byte("static"))
	require.True(t, handled)
	require.ErrorContains(t, err, "verified key possession")
}

func TestAssociationSelectionSeparatesVerifiedSubjectsAndAnonymousFallback(t *testing.T) {
	svc, _ := newAssociatedService(t)
	base := associationAdapter(t, "hostA", bconn.TransportSsh)
	first, _, err := svc.resolveAuthenticatedSession(base, []byte("static"))
	require.NoError(t, err)
	other := base
	actor := other.auth.(associationActor)
	actor.identity.Subject = "different-verified-subject"
	other.auth = actor
	second, _, err := svc.resolveAuthenticatedSession(other, []byte("static"))
	require.NoError(t, err)
	require.NotEqual(t, first.Id(), second.Id())
	actor.identity = authentication.Anonymous()
	other.auth = actor
	_, handled, err := svc.resolveAuthenticatedSession(other, []byte("static"))
	require.NoError(t, err)
	require.False(t, handled, "anonymous callers must not share through actor equality")
}

func TestRealSshRememberedKeyCannotBypassBoundTarget(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		target := &configuration.EnvironmentSsh{}
		require.NoError(t, target.SetDefaults())
		target.Address = template.MustNewString("127.0.0.1:1")
		target.User = template.MustNewString("{{ .connection.Id }}") // Different effective account on every connection.
		target.AcceptAllHostKeys = true                              // No downstream execution/connection is opened by this test.
		conf.Flows[0].Environment.V = target
	})
	first := server.mustDial(t)
	defer first.Close()
	var original session.Session
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(_ context.Context, sess session.Session) (bool, error) { original = sess; return false, nil }, nil))
	require.NotNil(t, original)
	require.NoError(t, original.AddPublicKey(t.Context(), server.signer.PublicKey()))
	second := server.mustDial(t)
	defer second.Close()
	count := 0
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 2, count, "remembered key must not skip association target checks")
}

func TestRealSshPrimaryLoginsShareAssociationAcrossKeyPasswordAndRequestingCase(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Requirement.IncludedRequestingName = common.MustNewRegexp("(?i)^restricted-key-user$")
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:correct")
	})
	first := server.mustDial(t)
	one, err := first.NewSession()
	require.NoError(t, err)
	require.NoError(t, one.Run("first"))
	second, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{User: strings.ToUpper(server.username), Auth: []gossh.AuthMethod{gossh.Password("correct")}, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}) //nolint:gosec // Test-local server.
	require.NoError(t, err)
	defer second.Close()
	two, err := second.NewSession()
	require.NoError(t, err)
	require.NoError(t, two.Run("second"))
	var sessions []session.Session
	require.NoError(t, server.service.sessions.FindAll(t.Context(), func(_ context.Context, candidate session.Session) (bool, error) {
		sessions = append(sessions, candidate)
		return true, nil
	}, nil))
	require.Len(t, sessions, 1)
	binding, err := session.AssociationOf(t.Context(), sessions[0])
	require.NoError(t, err)
	require.NotNil(t, binding)
	require.Equal(t, server.username, binding.Subject)
	server.service.sessionConnections.mutex.Lock()
	ids := make([]session.Id, 0, 2)
	for _, key := range server.service.sessionConnections.connections {
		ids = append(ids, key.id)
	}
	server.service.sessionConnections.mutex.Unlock()
	require.Len(t, ids, 2)
	require.Equal(t, ids[0], ids[1])
}
