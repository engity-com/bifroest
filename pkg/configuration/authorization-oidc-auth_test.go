package configuration

import (
	"testing"
)

func TestAuthorizationOidc_UnmarshalYAML(t *testing.T) {
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
				Issuer:           "https://foo-bar",
				ClientId:         "anId",
				ClientSecret:     "aSecret",
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
				Issuer:           "https://foo-bar",
				ClientId:         "anId",
				ClientSecret:     "aSecret",
				Scopes:           []string{"a", "b", "c"},
				RetrieveIdToken:  false,
				RetrieveUserInfo: true,
			},
		},
	)
}
