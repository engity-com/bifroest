package authorization

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

type characterizationFactoryConfig struct {
	configuration.AuthorizationNone
}
type characterizationFactoryAuthorizer struct {
	CloseableAuthorizer
	flow     configuration.FlowName
	denied   bool
	err      error
	attempts *[]configuration.FlowName
	closed   int
	onClose  func() error
}

func (this *characterizationFactoryAuthorizer) authorize(req Request) (Authorization, error) {
	*this.attempts = append(*this.attempts, this.flow)
	if this.err != nil {
		return nil, this.err
	}
	if this.denied {
		return Forbidden(req.Connection().Remote()), nil
	}
	return &none{flow: this.flow, remote: req.Connection().Remote()}, nil
}
func (this *characterizationFactoryAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	return this.authorize(req)
}
func (this *characterizationFactoryAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	return this.authorize(req)
}
func (this *characterizationFactoryAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	return this.authorize(req)
}
func (*characterizationFactoryAuthorizer) AuthenticationCapabilities(DiscoveryInput) AuthenticationCapabilities {
	return AuthenticationCapabilities{Password: true, PublicKey: true, KeyboardInteractive: true}
}
func (this *characterizationFactoryAuthorizer) Close() error {
	this.closed++
	if this.onClose != nil {
		return this.onClose()
	}
	return nil
}

func characterizationInstallFactory(t *testing.T, factory any) {
	t.Helper()
	key := reflect.TypeOf((*characterizationFactoryConfig)(nil))
	previous, existed := configurationTypeToAuthorizerFactory[key]
	configurationTypeToAuthorizerFactory[key] = factory
	t.Cleanup(func() {
		if existed {
			configurationTypeToAuthorizerFactory[key] = previous
		} else {
			delete(configurationTypeToAuthorizerFactory, key)
		}
	})
}

func characterizationFactoryFlows() configuration.Flows {
	return configuration.Flows{
		{Name: "first", Authorization: configuration.Authorization{V: &characterizationFactoryConfig{}}},
		{Name: "second", Authorization: configuration.Authorization{V: &characterizationFactoryConfig{}}},
	}
}

func TestPolicyRegressionRegisteredFacadeSelectionAndObserver(t *testing.T) {
	for _, method := range facadeSelectionMethods {
		for _, scenario := range []string{"first wins", "denial falls through", "failure stops"} {
			t.Run(method.name+"/"+scenario, func(t *testing.T) {
				var attempts, initialized []configuration.FlowName
				var created []*characterizationFactoryAuthorizer
				upstream := berrors.Network.Newf("provider failed")
				characterizationInstallFactory(t, func(ctx context.Context, flow configuration.FlowName, _ *characterizationFactoryConfig) (DiscoveryAuthorizer, error) {
					require.Same(t, t.Context(), ctx)
					initialized = append(initialized, flow)
					provider := &characterizationFactoryAuthorizer{flow: flow, attempts: &attempts}
					if flow == "first" {
						provider.denied = scenario == "denial falls through"
						if scenario == "failure stops" {
							provider.err = upstream
						}
					}
					created = append(created, provider)
					return provider, nil
				})
				flows := characterizationFactoryFlows()
				var observed []FlowAuthorizationObservation
				facade, err := NewAuthorizerFacadeWithObserver(t.Context(), &flows, func(_ context.Context, observation FlowAuthorizationObservation) error {
					observed = append(observed, observation)
					return nil
				})
				require.NoError(t, err)
				require.Equal(t, []configuration.FlowName{"first", "second"}, initialized)
				response, err := method.authorize(facade, &facadeSelectionRequest{name: "alice"})
				if scenario == "failure stops" {
					require.ErrorIs(t, err, upstream)
					require.True(t, berrors.Network.IsErr(err))
					require.Nil(t, response)
					require.Equal(t, FlowAuthorizationOutcomeFailed, observed[0].Outcome)
				} else {
					require.NoError(t, err)
					require.True(t, response.IsAuthorized())
					if scenario == "denial falls through" {
						require.Equal(t, configuration.FlowName("second"), response.Flow())
						require.Equal(t, FlowAuthorizationOutcomeDenied, observed[0].Outcome)
					} else {
						require.Equal(t, configuration.FlowName("first"), response.Flow())
					}
				}
				require.Len(t, observed, len(attempts))
				require.NoError(t, facade.Close())
				for _, provider := range created {
					require.Equal(t, 1, provider.closed)
				}
			})
		}
	}
}

func TestPolicyRegressionFacadeInitializationFailureOwnership(t *testing.T) {
	var attempts []configuration.FlowName
	first := &characterizationFactoryAuthorizer{flow: "first", attempts: &attempts}
	failure := errors.New("initialization failure")
	characterizationInstallFactory(t, func(_ context.Context, name configuration.FlowName, _ *characterizationFactoryConfig) (DiscoveryAuthorizer, error) {
		if name == "first" {
			return first, nil
		}
		return nil, failure
	})
	flows := characterizationFactoryFlows()
	facade, err := NewAuthorizerFacade(t.Context(), &flows)
	require.Nil(t, facade)
	require.ErrorIs(t, err, failure)
	require.ErrorContains(t, err, `flow "second"`)
	require.Equal(t, 1, first.closed, "the failed facade must close the resources it already owns")
	require.True(t, berrors.System.IsErr(err))
}

// A failed constructor returns no facade for the caller to close. Release every
// owned authorizer once in reverse order, retaining initialization and cleanup errors.
func TestPolicyRegressionRegisteredFacadeCleanupOrderAndErrorCategories(t *testing.T) {
	initializationErr := berrors.Network.Newf("provider initialization failed")
	firstCloseErr := berrors.Permission.Newf("first cleanup failed")
	secondCloseErr := berrors.System.Newf("second cleanup failed")
	for _, failedAt := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("failure at %d", failedAt), func(t *testing.T) {
			flows := characterizationFactoryFlows()
			flows = append(flows, configuration.Flow{Name: "third", Authorization: configuration.Authorization{V: &characterizationFactoryConfig{}}})
			var initialized, closed []configuration.FlowName
			var providers []*characterizationFactoryAuthorizer
			characterizationInstallFactory(t, func(_ context.Context, name configuration.FlowName, _ *characterizationFactoryConfig) (DiscoveryAuthorizer, error) {
				if len(initialized) == failedAt {
					return nil, initializationErr
				}
				initialized = append(initialized, name)
				provider := &characterizationFactoryAuthorizer{flow: name, onClose: func() error {
					closed = append(closed, name)
					if name == "first" {
						return firstCloseErr
					}
					return secondCloseErr
				}}
				providers = append(providers, provider)
				return provider, nil
			})
			facade, err := NewAuthorizerFacade(t.Context(), &flows)
			require.Nil(t, facade)
			require.ErrorIs(t, err, initializationErr)
			require.True(t, berrors.Network.IsErr(err))
			require.ErrorContains(t, err, fmt.Sprintf("flow %q", flows[failedAt].Name))
			require.Len(t, initialized, failedAt)
			require.Len(t, closed, failedAt)
			for index := range initialized {
				require.Equal(t, initialized[len(initialized)-1-index], closed[index])
				require.Equal(t, 1, providers[index].closed)
			}
			if failedAt >= 1 {
				require.ErrorIs(t, err, firstCloseErr)
				require.True(t, berrors.Permission.IsErr(err))
			} else {
				require.NotErrorIs(t, err, firstCloseErr)
			}
			if failedAt >= 2 {
				require.ErrorIs(t, err, secondCloseErr)
				require.True(t, berrors.System.IsErr(err))
			} else {
				require.NotErrorIs(t, err, secondCloseErr)
			}
		})
	}
}

func TestPolicyRegressionFacadeNilAndUnsupportedFactories(t *testing.T) {
	for _, flows := range []*configuration.Flows{nil, {}} {
		facade, err := NewAuthorizerFacade(t.Context(), flows)
		require.NoError(t, err)
		require.Empty(t, facade.entries)
		require.NoError(t, facade.Close())
	}
	characterizationInstallFactory(t, func(context.Context, configuration.FlowName, *characterizationFactoryConfig) (*characterizationFactoryAuthorizer, error) {
		return nil, nil
	})
	flows := characterizationFactoryFlows()
	_, err := NewAuthorizerFacade(t.Context(), &flows)
	require.ErrorContains(t, err, "factory returned nil")
	require.True(t, berrors.Config.IsErr(err))
	delete(configurationTypeToAuthorizerFactory, reflect.TypeOf((*characterizationFactoryConfig)(nil)))
	_, err = NewAuthorizerFacade(t.Context(), &flows)
	require.ErrorContains(t, err, "cannot handle authorization type")
	require.True(t, berrors.Config.IsErr(err))
}

func TestPolicyRegressionFacadeObserverFailureDoesNotFallThrough(t *testing.T) {
	var attempts []configuration.FlowName
	characterizationInstallFactory(t, func(_ context.Context, flow configuration.FlowName, _ *characterizationFactoryConfig) (DiscoveryAuthorizer, error) {
		return &characterizationFactoryAuthorizer{flow: flow, attempts: &attempts}, nil
	})
	failure := berrors.Permission.Newf("observation failed")
	flows := characterizationFactoryFlows()
	facade, err := NewAuthorizerFacadeWithObserver(t.Context(), &flows, func(_ context.Context, event FlowAuthorizationObservation) error {
		require.Equal(t, FlowAuthorizationOutcomeAccepted, event.Outcome)
		return failure
	})
	require.NoError(t, err)
	response, err := facade.AuthorizePassword(&facadeSelectionRequest{name: "alice"})
	require.Nil(t, response)
	require.ErrorIs(t, err, failure)
	require.True(t, berrors.Permission.IsErr(err))
	require.Equal(t, []configuration.FlowName{"first"}, attempts)
	require.NoError(t, facade.Close())
}

type characterizationRequestBase interface {
	PublicKeyRequest
	InteractiveRequest
}
type characterizationRequest struct {
	characterizationRequestBase
	ctx context.Context
}

func (this characterizationRequest) Context() context.Context { return this.ctx }
func (characterizationRequest) Connection() connection.Connection {
	return facadeSelectionConnection{name: "requested"}
}
func (characterizationRequest) GetField(name string) (any, bool, error) {
	if name == "marker" {
		return "parent", true, nil
	}
	return nil, false, fmt.Errorf("missing parent field")
}

func TestPolicyRegressionAuthorizationWrapperDataAndUnscopedFunctions(t *testing.T) {
	t.Setenv("BIFROEST_CHARACTERIZATION_AUTH_WRAPPERS", "host")
	base := characterizationRequest{ctx: t.Context()}
	bounded, cancel := context.WithCancel(t.Context())
	defer cancel()
	for _, test := range []struct {
		name   string
		value  any
		marker bool
	}{
		{"remote name", remoteNameRequest{base}, true},
		{"primary key", primaryPublicKeyRequest{base}, true},
		{"remembered SSH", sshSessionResumeRequest{PublicKeyRequest: base}, true},
		{"resume key", resumePublicKeyRequest{Request: base}, true},
		{"bounded OIDC code", &oidcCodeRequest{InteractiveRequest: base, ctx: bounded}, true},
		{"OIDC message", &oidcLoginMessageContext{request: base, code: "code", url: "https://fixture.invalid"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := template.MustNewString(`{{ env "BIFROEST_CHARACTERIZATION_AUTH_WRAPPERS" }}`).Render(test.value)
			require.NoError(t, err)
			require.Equal(t, "host", value)
			value, err = template.MustNewString(`{{ .marker }}`).Render(test.value)
			if test.marker {
				require.NoError(t, err)
				require.Equal(t, "parent", value)
			} else {
				require.NoError(t, err)
				require.Empty(t, value, "baseline invalid=nil/nil=empty handling of the narrower wrapper")
			}
		})
	}
	name, err := resolveRemoteName(base, template.MustNewString(`{{ env "BIFROEST_CHARACTERIZATION_AUTH_WRAPPERS" }}`))
	require.NoError(t, err)
	require.Equal(t, "host", name)
	message, err := RenderOidcSshLoginMessage(base, template.MustNewString(`{{ .marker }}:{{ .code }}:{{ .codeRequired }}`), "https://fixture.invalid", "fixture-code", true)
	require.NoError(t, err)
	require.Equal(t, "parent:fixture-code:true", message)
	code := &oidcCodeRequest{InteractiveRequest: base, ctx: bounded}
	require.Same(t, bounded, code.Context())
	cancel()
	require.ErrorIs(t, code.Context().Err(), context.Canceled)
}
