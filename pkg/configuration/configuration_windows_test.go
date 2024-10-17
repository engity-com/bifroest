//go:build windows

package configuration

import (
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestConfiguration_UnmarshalYAML(t *testing.T) {
	testlog.Hook(t)

	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[Configuration]{
			name:          "empty",
			yaml:          ``,
			expectedError: `EOF`,
		},
		unmarshalYamlTestCase[Configuration]{
			name:          "flows-missing",
			yaml:          `{}`,
			expectedError: `[flows] required but absent`,
		},
		unmarshalYamlTestCase[Configuration]{
			name:          "flows-empty",
			yaml:          `flows: []`,
			expectedError: `[flows] required but absent`,
		},
		unmarshalYamlTestCase[Configuration]{
			name: "required-set",
			yaml: `flows:
- name: foo
  authorization:
    type: oidcDeviceAuth
    issuer: https://foo-bar
    clientId: anId
    clientSecret: aSecret
  environment:
    type: local`,
			expected: Configuration{
				Ssh: Ssh{
					Addresses: DefaultSshAddresses,
					Keys: Keys{
						HostKeys:               DefaultHostKeyLocations,
						RsaRestriction:         crypto.DefaultRsaRestriction,
						DsaRestriction:         crypto.DefaultDsaRestriction,
						EcdsaRestriction:       crypto.DefaultEcdsaRestriction,
						Ed25519Restriction:     crypto.DefaultEd25519Restriction,
						RememberMeNotification: DefaultRememberMeNotification,
					},
					IdleTimeout:    DefaultSshIdleTimeout,
					MaxTimeout:     DefaultSshMaxTimeout,
					MaxAuthTries:   DefaultSshMaxAuthTries,
					MaxConnections: DefaultSshMaxConnections,
					Banner:         DefaultSshBanner,
					PreparationMessages: PreparationMessages{{
						Id:     DefaultPreparationMessageId,
						Flow:   DefaultPreparationMessageFlow,
						Start:  DefaultPreparationMessageStart,
						Update: DefaultPreparationMessageUpdate,
						End:    DefaultPreparationMessageEnd,
						Error:  DefaultPreparationMessageError,
					}},
				},
				Session: Session{&SessionFs{
					IdleTimeout:    DefaultSessionIdleTimeout,
					MaxTimeout:     DefaultSessionMaxTimeout,
					MaxConnections: DefaultSessionMaxConnections,
					Storage:        DefaultSessionFsStorage,
					FileMode:       DefaultSessionFsFileMode,
				}},
				Flows: []Flow{{
					Name: "foo",
					Requirement: Requirement{
						IncludedRequestingName: common.MustNewRegexp(""),
						ExcludedRequestingName: common.MustNewRegexp(""),
					},
					Authorization: Authorization{&AuthorizationOidcDeviceAuth{
						Issuer:           template.MustNewUrl("https://foo-bar"),
						ClientId:         template.MustNewString("anId"),
						ClientSecret:     template.MustNewString("aSecret"),
						Scopes:           DefaultAuthorizationOidcScopes,
						RetrieveIdToken:  DefaultAuthorizationOidcRetrieveIdToken,
						RetrieveUserInfo: DefaultAuthorizationOidcRetrieveUserInfo,
					}},
					Environment: Environment{&EnvironmentLocal{
						LoginAllowed:          DefaultEnvironmentLocalLoginAllowed,
						Banner:                DefaultEnvironmentLocalBanner,
						ShellCommand:          DefaultEnvironmentLocalShellCommand,
						ExecCommandPrefix:     DefaultEnvironmentLocalExecCommandPrefix,
						Directory:             DefaultEnvironmentLocalDirectory,
						PortForwardingAllowed: DefaultEnvironmentLocalPortForwardingAllowed,
					}},
				}},
				Alternatives: Alternatives{
					DownloadUrl: DefaultAlternativesDownloadUrl,
					Location:    DefaultAlternativesLocation,
				},
				HouseKeeping: HouseKeeping{
					Every:          DefaultHouseKeepingEvery,
					InitialDelay:   DefaultHouseKeepingInitialDelay,
					AutoRepair:     DefaultHouseKeepingAutoRepair,
					KeepExpiredFor: DefaultHouseKeepingKeepExpiredFor,
				},
				StartMessage: DefaultStartMessage,
			},
		},
	)
}
