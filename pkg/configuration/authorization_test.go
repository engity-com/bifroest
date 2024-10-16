package configuration

import (
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuthorization_UnmarshalYAML(t *testing.T) {
	testlog.Hook(t)

	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[Authorization]{
			name:          "empty",
			yaml:          ``,
			expectedError: `EOF`,
		},
		unmarshalYamlTestCase[Authorization]{
			name:          "type-missing",
			yaml:          `{}`,
			expectedError: `[type] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name:          "issuer-missing",
			yaml:          `type: oidcDeviceAuth`,
			expectedError: `[issuer] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "client-id-missing",
			yaml: `type: oidcDeviceAuth
issuer: https://foo-bar`,
			expectedError: `[clientId] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "client-secret-missing",
			yaml: `type: oidcDeviceAuth
issuer: https://foo-bar
clientId: abc`,
			expectedError: `[clientSecret] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "required-set",
			yaml: `type: oidcDeviceAuth
issuer: https://foo-bar
clientId: anId
clientSecret: aSecret`,
			expected: Authorization{&AuthorizationOidcDeviceAuth{
				Issuer:           template.MustNewUrl("https://foo-bar"),
				ClientId:         template.MustNewString("anId"),
				ClientSecret:     template.MustNewString("aSecret"),
				Scopes:           DefaultAuthorizationOidcScopes,
				RetrieveIdToken:  true,
				RetrieveUserInfo: false,
			}},
		},
	)
}
