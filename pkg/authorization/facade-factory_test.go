package authorization

import (
	"context"
	"errors"
	"net/http"
	"testing"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

// Unexpected restoration calls panic through the embedded nil interface. These
// adapters provide assumed authentication outcomes, not credentials or sessions.
type facadeFactoryTestAuthorizer struct {
	CloseableAuthorizer
	flow         configuration.FlowName
	response     Authorization
	err          error
	attempts     *[]configuration.FlowName
	capabilities AuthenticationCapabilities
	closed       int
	onClose      func() error
}

func (this *facadeFactoryTestAuthorizer) authorize(Request) (Authorization, error) {
	*this.attempts = append(*this.attempts, this.flow)
	return this.response, this.err
}
func (this *facadeFactoryTestAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	return this.authorize(req)
}
func (this *facadeFactoryTestAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	return this.authorize(req)
}
func (this *facadeFactoryTestAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	return this.authorize(req)
}
func (this *facadeFactoryTestAuthorizer) AuthenticationCapabilities(DiscoveryInput) AuthenticationCapabilities {
	return this.capabilities
}
func (this *facadeFactoryTestAuthorizer) Close() error {
	this.closed++
	if this.onClose != nil {
		return this.onClose()
	}
	return nil
}

type facadeFactoryTestAuthorization struct {
	Authorization
	flow configuration.FlowName
}

func (facadeFactoryTestAuthorization) IsAuthorized() bool                { return true }
func (this facadeFactoryTestAuthorization) Flow() configuration.FlowName { return this.flow }
func (facadeFactoryTestAuthorization) FindSession() session.Session      { return nil }
func (facadeFactoryTestAuthorization) AuthorizationKind() string         { return "assumed" }

type facadeFactoryTestRequest struct {
	facadeSelectionRequest
	selection connection.Selection
}

func (this *facadeFactoryTestRequest) Selection() connection.Selection { return this.selection }
func (*facadeFactoryTestRequest) Sessions() session.Repository {
	panic("selection must not access a session repository")
}
func (*facadeFactoryTestRequest) Prompt(string, bool) (string, error) {
	panic("assumed authentication must not prompt for credentials")
}

func newFacadeFactoryTestRequest(selection connection.Selection) *facadeFactoryTestRequest {
	return &facadeFactoryTestRequest{facadeSelectionRequest: facadeSelectionRequest{name: "alice"}, selection: selection}
}

type facadeFactoryDenyTransport struct{ calls int }

func (this *facadeFactoryDenyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	this.calls++
	return nil, errors.New("runtime HTTP dependency must not be called")
}

func TestFacadeFactoryDoesNotInitializeRegisteredAuthorizers(t *testing.T) {
	transport := &facadeFactoryDenyTransport{}
	ctx := coidc.ClientContext(t.Context(), &http.Client{Transport: transport})
	flow := selectionTestFlow("corporate")
	flow.Authorization = configuration.Authorization{
		Reference: "corporate",
		V: &configuration.AuthorizationOidcDeviceAuth{
			Issuer: template.MustNewUrl("https://idp.example.invalid"),
		},
	}
	flows := configuration.Flows{flow}
	var attempts []configuration.FlowName
	provider := &facadeFactoryTestAuthorizer{flow: flow.Name, attempts: &attempts, response: facadeFactoryTestAuthorization{flow: flow.Name}}
	factoryCalls := 0
	facade, err := NewAuthorizerFacadeWithFactory(ctx, &flows, func(received context.Context, candidate *configuration.Flow) (DiscoveryAuthorizer, error) {
		factoryCalls++
		require.Same(t, ctx, received)
		require.Equal(t, flow, *candidate)
		return provider, nil
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, facade.Close()) })
	require.Equal(t, 1, factoryCalls)
	require.Zero(t, transport.calls, "construction must not fall back to registered OIDC discovery")

	auth, err := facade.AuthorizeInteractive(newFacadeFactoryTestRequest(connection.Selection{Transport: connection.TransportSsh}))
	require.NoError(t, err)
	require.True(t, auth.IsAuthorized())
	require.Equal(t, flow.Name, auth.Flow())
	require.Equal(t, []configuration.FlowName{flow.Name}, attempts)
	require.Zero(t, transport.calls)
}

func TestFacadeFactoryPreservesSelectionAndResponseValidation(t *testing.T) {
	policyErr := errors.New("policy dependency failed")
	observerErr := errors.New("observation failed")
	for _, method := range facadeSelectionMethods {
		for _, test := range []struct {
			name        string
			first       Authorization
			err         error
			observerErr error
			attempts    []configuration.FlowName
			outcome     FlowAuthorizationOutcome
			errorText   string
		}{
			{name: "denial falls through", first: Forbidden(nil), attempts: []configuration.FlowName{"first", "second"}, outcome: FlowAuthorizationOutcomeDenied},
			{name: "acceptance stops", first: facadeFactoryTestAuthorization{flow: "first"}, attempts: []configuration.FlowName{"first"}, outcome: FlowAuthorizationOutcomeAccepted},
			{name: "error stops", err: policyErr, attempts: []configuration.FlowName{"first"}, outcome: FlowAuthorizationOutcomeFailed, errorText: policyErr.Error()},
			{name: "nil response fails", attempts: []configuration.FlowName{"first"}, outcome: FlowAuthorizationOutcomeFailed, errorText: "nil response"},
			{name: "foreign flow fails", first: facadeFactoryTestAuthorization{flow: "foreign"}, attempts: []configuration.FlowName{"first"}, outcome: FlowAuthorizationOutcomeFailed, errorText: "response for flow"},
			{name: "observer error stops", first: facadeFactoryTestAuthorization{flow: "first"}, observerErr: observerErr, attempts: []configuration.FlowName{"first"}, outcome: FlowAuthorizationOutcomeAccepted, errorText: observerErr.Error()},
		} {
			t.Run(method.name+"/"+test.name, func(t *testing.T) {
				flows := configuration.Flows{selectionTestFlow("first"), selectionTestFlow("second"), selectionTestFlow("third")}
				var attempts []configuration.FlowName
				var observations []FlowAuthorizationObservation
				facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(_ context.Context, flow *configuration.Flow) (DiscoveryAuthorizer, error) {
					provider := &facadeFactoryTestAuthorizer{flow: flow.Name, attempts: &attempts, response: facadeFactoryTestAuthorization{flow: flow.Name}}
					if flow.Name == "first" {
						provider.response, provider.err = test.first, test.err
					}
					return provider, nil
				}, func(_ context.Context, observation FlowAuthorizationObservation) error {
					observations = append(observations, observation)
					return test.observerErr
				})
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, facade.Close()) })
				auth, err := method.authorize(facade, newFacadeFactoryTestRequest(connection.Selection{Transport: connection.TransportSsh}))
				if test.errorText != "" {
					require.ErrorContains(t, err, test.errorText)
					require.Nil(t, auth)
				} else {
					require.NoError(t, err)
					require.True(t, auth.IsAuthorized())
					require.Equal(t, test.attempts[len(test.attempts)-1], auth.Flow())
				}
				if test.err != nil {
					require.ErrorIs(t, err, test.err)
				}
				if test.observerErr != nil {
					require.ErrorIs(t, err, test.observerErr)
				}
				require.Equal(t, test.attempts, attempts)
				require.Len(t, observations, len(attempts))
				require.Equal(t, test.outcome, observations[0].Outcome)
				require.Equal(t, "first", observations[0].Flow.String())
			})
		}
	}
}

func TestFacadeFactoryPreservesHttpPinningAndRequirements(t *testing.T) {
	policyErr := errors.New("published policy failed")
	for _, method := range facadeSelectionMethods {
		for _, test := range []struct {
			name      string
			configure func(*configuration.Flow)
			denied    bool
			err       error
			attempted bool
		}{
			{name: "published flow wins", attempted: true},
			{name: "published denial does not fall through", denied: true, attempted: true},
			{name: "published error does not fall through", err: policyErr, attempted: true},
			{name: "name mismatch does not fall through", configure: func(flow *configuration.Flow) {
				flow.Requirement.IncludedRequestingName = common.MustNewRegexp("^other$")
			}},
			{name: "nameless mismatch does not fall through", configure: func(flow *configuration.Flow) {
				no := false
				flow.Http.RequestUser = &no
			}},
			{name: "slug mismatch does not fall through", configure: func(flow *configuration.Flow) {
				flow.Requirement.Http.ExcludedSlug = common.MustNewRegexp("^servers/Production$")
			}},
		} {
			t.Run(method.name+"/"+test.name, func(t *testing.T) {
				published := selectionTestFlow("published")
				published.DiscoverAsSlug = "servers/Production"
				published.Requirement.Http.IncludedHost = common.MustNewRegexp(`^app\.example$`)
				if test.configure != nil {
					test.configure(&published)
				}
				flows := configuration.Flows{selectionTestFlow("generic-first"), published, selectionTestFlow("generic-last")}
				var attempts []configuration.FlowName
				facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(_ context.Context, flow *configuration.Flow) (DiscoveryAuthorizer, error) {
					provider := &facadeFactoryTestAuthorizer{flow: flow.Name, attempts: &attempts, response: facadeFactoryTestAuthorization{flow: flow.Name}}
					if flow.Name == "published" {
						provider.err = test.err
						if test.denied {
							provider.response = Forbidden(nil)
						}
					}
					return provider, nil
				}, nil)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, facade.Close()) })
				request := newFacadeFactoryTestRequest(connection.Selection{Transport: connection.TransportHttp, Host: "APP.EXAMPLE.:443", Slug: "servers/Production"})
				auth, err := method.authorize(facade, request)
				if test.err != nil {
					require.ErrorIs(t, err, test.err)
					require.Nil(t, auth)
				} else {
					require.NoError(t, err)
					require.Equal(t, test.attempted && !test.denied, auth.IsAuthorized())
					if auth.IsAuthorized() {
						require.Equal(t, published.Name, auth.Flow())
					}
				}
				if test.attempted {
					require.Equal(t, []configuration.FlowName{published.Name}, attempts)
				} else {
					require.Empty(t, attempts)
				}
			})
		}
	}
}

func TestFacadeFactoryIsPerInstance(t *testing.T) {
	flows := configuration.Flows{selectionTestFlow("selected")}
	for _, accepted := range []bool{false, true, false} {
		var attempts []configuration.FlowName
		facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(_ context.Context, flow *configuration.Flow) (DiscoveryAuthorizer, error) {
			response := Forbidden(nil)
			if accepted {
				response = facadeFactoryTestAuthorization{flow: flow.Name}
			}
			return &facadeFactoryTestAuthorizer{flow: flow.Name, attempts: &attempts, response: response}, nil
		}, nil)
		require.NoError(t, err)
		auth, err := facade.AuthorizePassword(newFacadeFactoryTestRequest(connection.Selection{Transport: connection.TransportSsh}))
		require.NoError(t, err)
		require.Equal(t, accepted, auth.IsAuthorized())
		require.NoError(t, facade.Close())
	}
	// A custom factory must not replace or alter the normal registered factory.
	registered, err := NewAuthorizerFacade(t.Context(), &flows)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, registered.Close()) })
	require.IsType(t, &NoneAuthorizer{}, registered.entries[0].CloseableAuthorizer)
}

func TestFacadeFactoryClosesInitializedAuthorizersOnFailure(t *testing.T) {
	initializationErr := berrors.Config.Newf("unsupported authentication dependency")
	closeErr := berrors.System.Newf("close failed")
	flows := configuration.Flows{selectionTestFlow("first"), selectionTestFlow("second"), selectionTestFlow("unsupported")}
	var closed []configuration.FlowName
	facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(_ context.Context, flow *configuration.Flow) (DiscoveryAuthorizer, error) {
		if flow.Name == "unsupported" {
			return nil, initializationErr
		}
		return &facadeFactoryTestAuthorizer{onClose: func() error {
			closed = append(closed, flow.Name)
			if flow.Name == "first" {
				return closeErr
			}
			return nil
		}}, nil
	}, nil)
	require.Nil(t, facade)
	require.ErrorIs(t, err, initializationErr)
	require.ErrorIs(t, err, closeErr)
	require.True(t, berrors.Config.IsErr(err))
	require.True(t, berrors.System.IsErr(err), "joined cleanup errors must retain their own category")
	require.ErrorContains(t, err, `flow "unsupported"`)
	require.Equal(t, []configuration.FlowName{"second", "first"}, closed)
}

func TestFacadeFactoryClassifiesUntypedInitializationFailures(t *testing.T) {
	upstream := errors.New("initialization failed")
	flows := configuration.Flows{selectionTestFlow("selected")}
	facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(context.Context, *configuration.Flow) (DiscoveryAuthorizer, error) {
		return nil, upstream
	}, nil)
	require.Nil(t, facade)
	require.ErrorIs(t, err, upstream)
	require.True(t, berrors.System.IsErr(err))
}

func TestFacadeFactoryRejectsNilDependencies(t *testing.T) {
	flows := configuration.Flows{selectionTestFlow("selected")}
	facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, nil, nil)
	require.ErrorContains(t, err, "factory is required")
	require.True(t, berrors.Config.IsErr(err))
	require.Nil(t, facade)
	for _, provider := range []DiscoveryAuthorizer{nil, (*facadeFactoryTestAuthorizer)(nil)} {
		facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(context.Context, *configuration.Flow) (DiscoveryAuthorizer, error) {
			return provider, nil
		}, nil)
		require.ErrorContains(t, err, "factory returned nil")
		require.True(t, berrors.Config.IsErr(err))
		require.Nil(t, facade)
	}
}

func TestFacadeFactoryEmptyFlowsAndCloseOwnership(t *testing.T) {
	factory := func(context.Context, *configuration.Flow) (DiscoveryAuthorizer, error) {
		panic("empty flows must not initialize authorizers")
	}
	for _, flows := range []*configuration.Flows{nil, {}} {
		facade, err := NewAuthorizerFacadeWithFactory(t.Context(), flows, factory, nil)
		require.NoError(t, err)
		auth, err := facade.AuthorizePassword(newFacadeFactoryTestRequest(connection.Selection{Transport: connection.TransportSsh}))
		require.NoError(t, err)
		require.False(t, auth.IsAuthorized())
		require.NoError(t, facade.Close())
	}
	flows := configuration.Flows{selectionTestFlow("selected")}
	provider := &facadeFactoryTestAuthorizer{}
	facade, err := NewAuthorizerFacadeWithFactory(t.Context(), &flows, func(context.Context, *configuration.Flow) (DiscoveryAuthorizer, error) {
		return provider, nil
	}, nil)
	require.NoError(t, err)
	require.NoError(t, facade.Close())
	require.NoError(t, facade.Close())
	require.Equal(t, 1, provider.closed, "the facade must release each owned authorizer once")
}
