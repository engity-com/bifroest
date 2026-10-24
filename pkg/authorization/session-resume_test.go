package authorization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

type resumeTestRequest struct {
	Request
	sess       session.Session
	identity   authentication.Identity
	credential authentication.SessionCredential
	verified   bool
	selection  connection.Selection
}

func (this *resumeTestRequest) SessionPossessionVerified() bool         { return this.verified }
func (this *resumeTestRequest) SessionToResume() session.Session        { return this.sess }
func (this *resumeTestRequest) ResumeIdentity() authentication.Identity { return this.identity }
func (this *resumeTestRequest) ResumeCredential() authentication.SessionCredential {
	return this.credential
}
func (this *resumeTestRequest) Selection() connection.Selection { return this.selection }

func newSimpleResumeFixture(t *testing.T) (*AuthorizerFacade, *resumeTestRequest, *configuration.AuthorizationSimple) {
	t.Helper()
	conf := &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	facade, _ := newSelectionTestFacade(t, configuration.Flows{{Name: "selected", Authorization: configuration.Authorization{V: conf}}})
	base := newFacadeSelectionRequest(t, "alice")
	base.password = "correct"
	selected := facadeHttpRequest{base, connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	auth, err := facade.AuthorizePassword(selected)
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	identity, err := AuthenticationOf(auth)
	require.NoError(t, err)
	return facade, &resumeTestRequest{Request: selected, sess: auth.FindSession(), identity: identity, credential: authentication.SessionCredential{Kind: "simple", Method: "password"}, verified: true, selection: selected.selection}, conf
}

func TestSessionResumeRequiresVerifiedPossessionCurrentFlowKindAndIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "no proof", "HTTP disabled", "wrong method", "wrong kind", "wrong subject", "wrong issuer", "wrong flow", "SSH transport", "removed password", "removed user"} {
		t.Run(mode, func(t *testing.T) {
			facade, request, conf := newSimpleResumeFixture(t)
			switch mode {
			case "no proof":
				request.verified = false
				request.Request = nil // Must not even touch the repository/remote.
			case "HTTP disabled":
				no := false
				facade.entries[0].http.Enabled = &no
			case "wrong method":
				request.credential.Method = "client-verified"
			case "wrong kind":
				request.credential.Kind = "none"
			case "wrong subject":
				request.identity.Subject = "other"
			case "wrong issuer":
				request.identity.Issuer = "other"
			case "wrong flow":
				facade.entries[0].flow = "other"
			case "SSH transport":
				request.selection.Transport = connection.TransportSsh
			case "removed password":
				conf.Entries[0].Password = crypto.Password("")
			case "removed user":
				conf.Entries = nil
			}
			auth, err := facade.ResumeSession(request)
			if mode == "valid" {
				require.NoError(t, err)
				require.Equal(t, request.sess.Id(), auth.FindSession().Id())
				require.Equal(t, "alice", auth.Remote().User())
			} else {
				require.Error(t, err)
				require.Nil(t, auth)
			}
		})
	}
}

func TestSessionResumeNeverSelectsAnotherSessionOrAllocatesOne(t *testing.T) {
	facade, request, _ := newSimpleResumeFixture(t)
	before, err := request.sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	for range 3 {
		auth, err := facade.ResumeSession(request)
		require.NoError(t, err)
		require.Equal(t, request.sess.Id(), auth.FindSession().Id())
	}
	after, err := request.sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after)
	count := 0
	require.NoError(t, request.Sessions().FindAll(t.Context(), func(_ context.Context, _ session.Session) (bool, error) { count++; return true, nil }, nil))
	require.Equal(t, 1, count)
	_, err = request.sess.Dispose(t.Context())
	require.NoError(t, err)
	_, err = facade.ResumeSession(request)
	require.Error(t, err)
}

func TestSessionResumeRechecksPublishedPriorityAndAllCurrentRequirements(t *testing.T) {
	for _, mode := range []string{"published moved", "general name", "HTTP name", "host", "slug", "name collection disabled", "audit"} {
		t.Run(mode, func(t *testing.T) {
			facade, request, _ := newSimpleResumeFixture(t)
			switch mode {
			case "published moved":
				facade.flows = append(facade.flows, configuration.Flow{Name: "other", DiscoverAsSlug: "Work"})
				facade.entries = append(facade.entries, facaded{flow: "other", CloseableAuthorizer: &NoneAuthorizer{flow: "other", conf: &configuration.AuthorizationNone{}}})
			case "general name":
				facade.entries[0].requirement.IncludedRequestingName = common.MustNewRegexp("^other$")
			case "HTTP name":
				facade.entries[0].requirement.Http.IncludedRequestingName = common.MustNewRegexp("^other$")
			case "host":
				facade.entries[0].requirement.Http.IncludedHost = common.MustNewRegexp("^other.example.org$")
			case "slug":
				facade.entries[0].requirement.Http.IncludedSlug = common.MustNewRegexp("^Other$")
			case "name collection disabled":
				no := false
				facade.entries[0].http.RequestUser = &no
			case "audit":
				facade.observer = func(context.Context, FlowAuthorizationObservation) error { return os.ErrPermission }
			}
			auth, err := facade.ResumeSession(request)
			require.Error(t, err)
			require.Nil(t, auth)
		})
	}
}

func TestSessionResumeHtpasswdRechecksFileMembershipAndMissingFile(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(path, []byte("alice:"+string(hash)+"\n"), 0600))
	conf := &configuration.AuthorizationHtpasswd{}
	require.NoError(t, conf.File.Set(path))
	facade, _ := newSelectionTestFacade(t, configuration.Flows{{Name: "selected", Authorization: configuration.Authorization{V: conf}}})
	base := newFacadeSelectionRequest(t, "alice")
	base.password = "correct"
	selected := facadeHttpRequest{base, connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
	auth, err := facade.AuthorizePassword(selected)
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	identity, err := AuthenticationOf(auth)
	require.NoError(t, err)
	req := &resumeTestRequest{Request: selected, sess: auth.FindSession(), identity: identity, credential: authentication.SessionCredential{Kind: "htpasswd", Method: "password"}, verified: true, selection: selected.selection}
	_, err = facade.ResumeSession(req)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte("bob:"+string(hash)+"\n"), 0600))
	_, err = facade.ResumeSession(req)
	require.Error(t, err, "removed users cannot resume from a diagnostic snapshot")
	require.NoError(t, os.Remove(path))
	_, err = facade.ResumeSession(req)
	require.Error(t, err)
	stored, err := req.sess.AuthorizationToken(t.Context())
	require.NoError(t, err)
	var token htpasswdToken
	require.NoError(t, json.Unmarshal(stored, &token))
	require.Equal(t, "alice", token.User.Name)
}

func TestSessionResumeRechecksExactPrimaryCertificateWithoutRememberedKeyFallback(t *testing.T) {
	for _, mode := range []string{"valid restricted", "expired", "wrong principal", "removed CA", "unsupported critical option"} {
		t.Run(mode, func(t *testing.T) {
			facade, request, _ := newSimpleResumeFixture(t)
			authority, subject := newEvidenceTestSigner(t), newEvidenceTestSigner(t)
			cert := &ssh.Certificate{Key: subject.PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"alice"}, ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix()), Permissions: ssh.Permissions{Extensions: map[string]string{}}}
			simple := facade.entries[0].CloseableAuthorizer.(*SimpleAuthorizer)
			simple.trustedUserCAs = []ssh.PublicKey{authority.PublicKey()}
			switch mode {
			case "expired":
				cert.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix())
			case "wrong principal":
				cert.ValidPrincipals = []string{"other"}
			case "removed CA":
				simple.trustedUserCAs = nil
			case "unsupported critical option":
				cert.CriticalOptions = map[string]string{"unsupported": ""}
			}
			require.NoError(t, cert.SignCert(rand.Reader, authority))
			request.credential = authentication.SessionCredential{Kind: "simple", Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString(cert.Marshal())}
			auth, err := facade.ResumeSession(request)
			if mode == "valid restricted" {
				require.NoError(t, err)
				require.False(t, AuthorizedKeyPolicyOf(auth).PtyAllowed)
				require.False(t, AuthorizedKeyPolicyOf(auth).AgentForwardingAllowed)
			} else {
				require.Error(t, err)
				require.Nil(t, auth)
			}
		})
	}
}
