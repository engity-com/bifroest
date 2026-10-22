package authorization

import (
	"context"
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type facadeSelectionRequest struct {
	repository session.Repository
	name       string
	key        ssh.PublicKey
	password   string
	prompts    int
}

func (*facadeSelectionRequest) Context() context.Context { return context.Background() }
func (this *facadeSelectionRequest) Connection() connection.Connection {
	return facadeSelectionConnection{name: this.name}
}
func (this *facadeSelectionRequest) Sessions() session.Repository    { return this.repository }
func (*facadeSelectionRequest) Validate(Authorization) (bool, error) { return true, nil }
func (this *facadeSelectionRequest) RemotePublicKey() ssh.PublicKey  { return this.key }
func (this *facadeSelectionRequest) RemotePassword() string          { return this.password }
func (*facadeSelectionRequest) SendInfo(string) error                { return nil }
func (*facadeSelectionRequest) SendError(string) error               { return nil }
func (this *facadeSelectionRequest) Prompt(string, bool) (string, error) {
	this.prompts++
	return this.password, nil
}

type facadeSelectionConnection struct{ name string }

func (facadeSelectionConnection) Id() connection.Id       { return connection.Id{} }
func (this facadeSelectionConnection) Remote() net.Remote { return authenticationTestRemote(this.name) }
func (facadeSelectionConnection) Logger() log.Logger      { return log.GetRootLogger() }

type facadeHttpRequest struct {
	*facadeSelectionRequest
	selection connection.Selection
}

func (this facadeHttpRequest) Selection() connection.Selection { return this.selection }

// These tests exercise the selection boundary, not a browser signature adapter.
// In particular, providing a public key here is not a proof of key possession.
type facadeSelectionCredentialRequest interface {
	PublicKeyRequest
	PasswordRequest
	InteractiveRequest
}

var facadeSelectionMethods = []struct {
	name      string
	authorize func(*AuthorizerFacade, facadeSelectionCredentialRequest) (Authorization, error)
}{
	{"public-key", func(f *AuthorizerFacade, r facadeSelectionCredentialRequest) (Authorization, error) {
		return f.AuthorizePublicKey(r)
	}},
	{"password", func(f *AuthorizerFacade, r facadeSelectionCredentialRequest) (Authorization, error) {
		return f.AuthorizePassword(r)
	}},
	{"keyboard-interactive", func(f *AuthorizerFacade, r facadeSelectionCredentialRequest) (Authorization, error) {
		return f.AuthorizeInteractive(r)
	}},
}

func newFacadeSelectionRequest(t *testing.T, name string) *facadeSelectionRequest {
	t.Helper()
	var conf configuration.SessionFs
	require.NoError(t, conf.SetDefaults())
	conf.Storage = t.TempDir()
	repository, err := session.NewFacadeRepository(context.Background(), &configuration.Session{V: &conf})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return &facadeSelectionRequest{repository: repository, name: name, key: newUserCertificateTestSigner(t).PublicKey(), password: "wrong"}
}

func newSelectionTestFacade(t *testing.T, flows configuration.Flows) (*AuthorizerFacade, *[]FlowAuthorizationObservation) {
	t.Helper()
	var observations []FlowAuthorizationObservation
	facade, err := NewAuthorizerFacadeWithObserver(context.Background(), &flows, func(_ context.Context, observation FlowAuthorizationObservation) error {
		observations = append(observations, observation)
		return nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, facade.Close()) })
	return facade, &observations
}

func selectionTestFlow(name configuration.FlowName) configuration.Flow {
	return configuration.Flow{Name: name, Authorization: configuration.Authorization{V: &configuration.AuthorizationNone{}}}
}

func TestFacadeChecksTransportAndNameRulesBeforeEveryAuthenticationMethod(t *testing.T) {
	no := false
	for _, test := range []struct {
		name      string
		transport connection.Transport
		user      string
		configure func(*configuration.Flow)
		accepted  bool
	}{
		{name: "legacy SSH defaults", user: "alice", accepted: true},
		{name: "HTTP defaults", transport: connection.TransportHttp, user: "alice", accepted: true},
		{name: "SSH disabled", configure: func(f *configuration.Flow) { f.Ssh.Enabled = &no }},
		{name: "HTTP disabled leaves SSH enabled", configure: func(f *configuration.Flow) { f.Http.Enabled = &no }, accepted: true},
		{name: "HTTP disabled", transport: connection.TransportHttp, configure: func(f *configuration.Flow) { f.Http.Enabled = &no }},
		{name: "SSH disabled leaves HTTP enabled", transport: connection.TransportHttp, configure: func(f *configuration.Flow) { f.Ssh.Enabled = &no }, accepted: true},
		{name: "empty HTTP user without prompt", transport: connection.TransportHttp, configure: func(f *configuration.Flow) { f.Http.RequestUser = &no }, accepted: true},
		{name: "no hidden HTTP user", transport: connection.TransportHttp, user: "alice", configure: func(f *configuration.Flow) { f.Http.RequestUser = &no }},
		{name: "empty user still checked", transport: connection.TransportHttp, configure: func(f *configuration.Flow) {
			f.Http.RequestUser = &no
			f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^sso$`)
		}},
		{name: "general name rule on HTTP", transport: connection.TransportHttp, user: "bob", configure: func(f *configuration.Flow) { f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^alice$`) }},
		{name: "SSH specific name rule", user: "alice", configure: func(f *configuration.Flow) {
			f.Requirement.Ssh.ExcludedRequestingName = common.MustNewRegexp(`^alice$`)
		}},
		{name: "HTTP ignores SSH rule", transport: connection.TransportHttp, user: "alice", configure: func(f *configuration.Flow) {
			f.Requirement.Ssh.ExcludedRequestingName = common.MustNewRegexp(`^alice$`)
		}, accepted: true},
		{name: "HTTP specific name rule", transport: connection.TransportHttp, user: "alice", configure: func(f *configuration.Flow) {
			f.Requirement.Http.ExcludedRequestingName = common.MustNewRegexp(`^alice$`)
		}},
		{name: "SSH ignores HTTP rules", user: "alice", configure: func(f *configuration.Flow) {
			f.Requirement.Http.ExcludedRequestingName = common.MustNewRegexp(`^alice$`)
			f.Requirement.Http.IncludedHost = common.MustNewRegexp(`^other\.example$`)
			f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^other$`)
		}, accepted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, method := range facadeSelectionMethods {
				t.Run(method.name, func(t *testing.T) {
					flow := selectionTestFlow("selected")
					if test.configure != nil {
						test.configure(&flow)
					}
					facade, observations := newSelectionTestFacade(t, configuration.Flows{flow})
					base := newFacadeSelectionRequest(t, test.user)
					var request facadeSelectionCredentialRequest = base
					if test.transport != "" {
						request = facadeHttpRequest{base, connection.Selection{Transport: test.transport, Host: "APP.EXAMPLE:443"}}
					}
					auth, err := method.authorize(facade, request)
					require.NoError(t, err)
					require.Equal(t, test.accepted, auth.IsAuthorized())
					if test.accepted {
						require.Len(t, *observations, 1)
						require.Equal(t, configuration.FlowName("selected"), auth.Flow())
					} else {
						require.Empty(t, *observations, "unmatched requests must not reach an authorizer")
					}
					require.Zero(t, base.prompts)
				})
			}
		})
	}
}

func TestPublishedHttpSlugHasPriorityWithoutRequirementOrCredentialFallthrough(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*configuration.Flow)
		attempted bool
		accepted  bool
	}{
		{name: "published takes priority", accepted: true, attempted: true},
		{name: "general name mismatch", configure: func(f *configuration.Flow) { f.Requirement.IncludedRequestingName = common.MustNewRegexp(`^other$`) }},
		{name: "HTTP name mismatch", configure: func(f *configuration.Flow) {
			f.Requirement.Http.IncludedRequestingName = common.MustNewRegexp(`^other$`)
		}},
		{name: "slug include mismatch", configure: func(f *configuration.Flow) { f.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^other$`) }},
		{name: "slug excluded", configure: func(f *configuration.Flow) { f.Requirement.Http.ExcludedSlug = common.MustNewRegexp(`^servers/Foo$`) }},
		{name: "credentials rejected", configure: func(f *configuration.Flow) {
			f.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
		}, attempted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, method := range facadeSelectionMethods {
				t.Run(method.name, func(t *testing.T) {
					fixed := selectionTestFlow("published")
					fixed.DiscoverAsSlug = "servers/Foo"
					fixed.Requirement.Http.IncludedHost = common.MustNewRegexp(`^app\.example$`)
					if test.configure != nil {
						test.configure(&fixed)
					}
					facade, observations := newSelectionTestFacade(t, configuration.Flows{selectionTestFlow("generic-first"), fixed, selectionTestFlow("generic-last")})
					request := facadeHttpRequest{newFacadeSelectionRequest(t, "alice"), connection.Selection{Transport: connection.TransportHttp, Host: "APP.EXAMPLE.:443", Slug: "servers/Foo"}}
					auth, err := method.authorize(facade, request)
					require.NoError(t, err)
					require.Equal(t, test.accepted, auth.IsAuthorized())
					if test.accepted {
						require.Equal(t, configuration.FlowName("published"), auth.Flow())
					}
					if test.attempted {
						require.Len(t, *observations, 1)
						require.Equal(t, configuration.FlowName("published"), (*observations)[0].Flow)
					} else {
						require.Empty(t, *observations)
					}
				})
			}
		})
	}
}

func TestNonPublishedHttpSlugsUseConfigurationOrderAndCredentialFallback(t *testing.T) {
	no := false
	disabled := selectionTestFlow("http-disabled")
	disabled.Http.Enabled = &no
	otherHost := selectionTestFlow("other-host")
	otherHost.Requirement.Http.ExcludedHost = common.MustNewRegexp(`^app\.example$`)
	otherSlug := selectionTestFlow("other-slug")
	otherSlug.Requirement.Http.IncludedSlug = common.MustNewRegexp(`^notrequested$`)
	denied := selectionTestFlow("denied")
	denied.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}}}
	for _, slug := range []string{"", "unknown", "servers/Foo"} {
		for _, method := range facadeSelectionMethods {
			t.Run(slug+"/"+method.name, func(t *testing.T) {
				flows := configuration.Flows{disabled, otherHost, otherSlug, denied, selectionTestFlow("first-accepted"), selectionTestFlow("last")}
				facade, observations := newSelectionTestFacade(t, flows)
				request := facadeHttpRequest{newFacadeSelectionRequest(t, "alice"), connection.Selection{Transport: connection.TransportHttp, Host: "app.example", Slug: slug}}
				auth, err := method.authorize(facade, request)
				require.NoError(t, err)
				require.True(t, auth.IsAuthorized())
				require.Equal(t, configuration.FlowName("first-accepted"), auth.Flow())
				require.Len(t, *observations, 2)
				require.Equal(t, configuration.FlowName("denied"), (*observations)[0].Flow)
				require.Equal(t, FlowAuthorizationOutcomeDenied, (*observations)[0].Outcome)
			})
		}
	}
}

func TestMalformedOrAmbiguousSelectionNeverReachesAnAuthorizer(t *testing.T) {
	for _, selection := range []connection.Selection{
		{}, {Transport: "unknown"}, {Transport: connection.TransportHttp},
		{Transport: connection.TransportHttp, Host: "app.example/path"},
		{Transport: connection.TransportHttp, Host: "app.example", Slug: "../foo"},
		{Transport: connection.TransportSsh, Host: "app.example"},
	} {
		for _, method := range facadeSelectionMethods {
			facade, observations := newSelectionTestFacade(t, configuration.Flows{selectionTestFlow("generic")})
			request := facadeHttpRequest{newFacadeSelectionRequest(t, "alice"), selection}
			_, err := method.authorize(facade, request)
			require.Error(t, err)
			require.Empty(t, *observations)
		}
	}
	first, second := selectionTestFlow("first"), selectionTestFlow("second")
	first.DiscoverAsSlug, second.DiscoverAsSlug = "foo", "foo"
	for _, method := range facadeSelectionMethods {
		facade, observations := newSelectionTestFacade(t, configuration.Flows{selectionTestFlow("generic"), first, second})
		request := facadeHttpRequest{newFacadeSelectionRequest(t, "alice"), connection.Selection{Transport: connection.TransportHttp, Host: "app.example", Slug: "foo"}}
		_, err := method.authorize(facade, request)
		require.ErrorContains(t, err, "multiple flows")
		require.Empty(t, *observations)
	}
}

func TestHttpPublicKeyCertificateCannotFallThroughFromPublishedUnsupportedFlow(t *testing.T) {
	published := selectionTestFlow("published") // None deliberately does not support certificates.
	published.DiscoverAsSlug = "foo"
	fallback := selectionTestFlow("fallback")
	fallback.Authorization.V = &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{
		Name: "alice",
	}}}
	facade, observations := newSelectionTestFacade(t, configuration.Flows{fallback, published})
	request := facadeHttpRequest{newFacadeSelectionRequest(t, "alice"), connection.Selection{Transport: connection.TransportHttp, Host: "app.example", Slug: "foo"}}
	request.key = &ssh.Certificate{Key: request.key}
	auth, err := facade.AuthorizePublicKey(request)
	require.NoError(t, err)
	require.False(t, auth.IsAuthorized())
	require.Empty(t, *observations)
}
