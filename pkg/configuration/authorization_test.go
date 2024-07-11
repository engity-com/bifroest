package configuration

import (
	"testing"
)

func TestAuthorization_UnmarshalYAML(t *testing.T) {
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
			yaml:          `type: oidc`,
			expectedError: `[issuer] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "client-id-missing",
			yaml: `type: oidc
issuer: https://foo-bar`,
			expectedError: `[clientId] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "client-secret-missing",
			yaml: `type: oidc
issuer: https://foo-bar
clientId: abc`,
			expectedError: `[clientSecret] required but absent`,
		},
		unmarshalYamlTestCase[Authorization]{
			name: "required-set",
			yaml: `type: oidc
issuer: https://foo-bar
clientId: anId
clientSecret: aSecret`,
			expected: Authorization{&AuthorizationOidc{
				Issuer:           "https://foo-bar",
				ClientId:         "anId",
				ClientSecret:     "aSecret",
				Scopes:           DefaultAuthorizationOidcScopes,
				RetrieveIdToken:  true,
				RetrieveUserInfo: false,
			}},
		},
	)
}
