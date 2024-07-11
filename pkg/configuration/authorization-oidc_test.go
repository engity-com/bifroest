package configuration

import (
	"testing"
)

func TestAuthorizationOidc_UnmarshalYAML(t *testing.T) {
	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[AuthorizationOidc]{
			name:          "empty",
			yaml:          ``,
			expectedError: `EOF`,
		},
		unmarshalYamlTestCase[AuthorizationOidc]{
			name:          "issuer-missing",
			yaml:          `{}`,
			expectedError: `[issuer] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidc]{
			name:          "client-id-missing",
			yaml:          `issuer: https://foo-bar`,
			expectedError: `[clientId] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidc]{
			name: "client-secret-missing",
			yaml: `issuer: https://foo-bar
clientId: abc`,
			expectedError: `[clientSecret] required but absent`,
		},
		unmarshalYamlTestCase[AuthorizationOidc]{
			name: "required-set",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret`,
			expected: AuthorizationOidc{
				Issuer:           "https://foo-bar",
				ClientId:         "anId",
				ClientSecret:     "aSecret",
				Scopes:           DefaultAuthorizationOidcScopes,
				RetrieveIdToken:  true,
				RetrieveUserInfo: false,
			},
		},
		unmarshalYamlTestCase[AuthorizationOidc]{
			name: "all-set",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
scopes: [a,b,c]
retrieveIdToken: false
retrieveUserInfo: true`,
			expected: AuthorizationOidc{
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
