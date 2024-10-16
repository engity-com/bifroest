package configuration

import (
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"

	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuthorizationOidc_UnmarshalYAML(t *testing.T) {
	testlog.Hook(t)

	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name:          "empty",
			yaml:          ``,
			expectedError: `EOF`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name:          "issuer-missing",
			yaml:          `{}`,
			expectedError: `[issuer] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name:          "client-id-missing",
			yaml:          `issuer: https://foo-bar`,
			expectedError: `[clientId] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "client-secret-missing",
			yaml: `issuer: https://foo-bar
clientId: abc`,
			expectedError: `[clientSecret] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "required-set",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:           template.MustNewUrl("https://foo-bar"),
				ClientId:         template.MustNewString("anId"),
				ClientSecret:     template.MustNewString("aSecret"),
				Scopes:           DefaultAuthorizationOidcScopes,
				RetrieveIdToken:  true,
				RetrieveUserInfo: false,
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "all-set",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
scopes: [a,b,c]
retrieveIdToken: false
retrieveUserInfo: true`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:           template.MustNewUrl("https://foo-bar"),
				ClientId:         template.MustNewString("anId"),
				ClientSecret:     template.MustNewString("aSecret"),
				Scopes:           template.MustNewStrings("a", "b", "c"),
				RetrieveIdToken:  false,
				RetrieveUserInfo: true,
			},
		},
	)
}
