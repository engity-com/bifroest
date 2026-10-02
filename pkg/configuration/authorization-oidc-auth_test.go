package configuration

import (
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
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
				Issuer:                template.MustNewUrl("https://foo-bar"),
				ClientId:              template.MustNewString("anId"),
				ClientSecret:          template.MustNewString("aSecret"),
				Scopes:                DefaultAuthorizationOidcScopes,
				RetrieveIdToken:       true,
				RetrieveUserInfo:      false,
				ForceDisposeSessionOn: DefaultAuthorizationOidcForceDisposeSessionOn,
				RefreshToken: AuthorizationOidcRefreshToken{
					Mode:              DefaultAuthorizationOidcRefreshTokenMode,
					AtLifetimePercent: DefaultAuthorizationOidcRefreshTokenAtLifetimePercent,
					FallbackEvery:     DefaultAuthorizationOidcRefreshTokenFallbackEvery,
					MaxUnverifiedFor:  DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor,
				},
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "all-set",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
scopes: [a,b,c]
retrieveIdToken: false
retrieveUserInfo: true
forceDisposeSessionOn: lostAccess
refreshToken:
  mode: proactive
  atLifetimePercent: 99
  fallbackEvery: 5m
  maxUnverifiedFor: 1h`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:                template.MustNewUrl("https://foo-bar"),
				ClientId:              template.MustNewString("anId"),
				ClientSecret:          template.MustNewString("aSecret"),
				Scopes:                template.MustNewStrings("a", "b", "c"),
				RetrieveIdToken:       false,
				RetrieveUserInfo:      true,
				ForceDisposeSessionOn: "lostAccess",
				RefreshToken: AuthorizationOidcRefreshToken{
					Mode:              "proactive",
					AtLifetimePercent: 99,
					FallbackEvery:     common.MustNewDuration("5m"),
					MaxUnverifiedFor:  common.MustNewDuration("1h"),
				},
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "partial-refresh-token",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
forceDisposeSessionOn: " lostAccess "
refreshToken:
  mode: " proactive "
  atLifetimePercent: 1`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:                template.MustNewUrl("https://foo-bar"),
				ClientId:              template.MustNewString("anId"),
				ClientSecret:          template.MustNewString("aSecret"),
				Scopes:                DefaultAuthorizationOidcScopes,
				RetrieveIdToken:       true,
				ForceDisposeSessionOn: "lostAccess",
				RefreshToken: AuthorizationOidcRefreshToken{
					Mode:              "proactive",
					AtLifetimePercent: 1,
					FallbackEvery:     DefaultAuthorizationOidcRefreshTokenFallbackEvery,
					MaxUnverifiedFor:  DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor,
				},
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "empty-refresh-token",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken: {}`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:                template.MustNewUrl("https://foo-bar"),
				ClientId:              template.MustNewString("anId"),
				ClientSecret:          template.MustNewString("aSecret"),
				Scopes:                DefaultAuthorizationOidcScopes,
				RetrieveIdToken:       true,
				ForceDisposeSessionOn: DefaultAuthorizationOidcForceDisposeSessionOn,
				RefreshToken: AuthorizationOidcRefreshToken{
					Mode:              DefaultAuthorizationOidcRefreshTokenMode,
					AtLifetimePercent: DefaultAuthorizationOidcRefreshTokenAtLifetimePercent,
					FallbackEvery:     DefaultAuthorizationOidcRefreshTokenFallbackEvery,
					MaxUnverifiedFor:  DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor,
				},
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "legacy-opt-out",
			yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
forceDisposeSessionOn: never
refreshToken:
  mode: never`,
			expected: AuthorizationOidcDeviceAuth{
				Issuer:                template.MustNewUrl("https://foo-bar"),
				ClientId:              template.MustNewString("anId"),
				ClientSecret:          template.MustNewString("aSecret"),
				Scopes:                DefaultAuthorizationOidcScopes,
				RetrieveIdToken:       true,
				ForceDisposeSessionOn: "never",
				RefreshToken: AuthorizationOidcRefreshToken{
					Mode:              "never",
					AtLifetimePercent: DefaultAuthorizationOidcRefreshTokenAtLifetimePercent,
					FallbackEvery:     DefaultAuthorizationOidcRefreshTokenFallbackEvery,
					MaxUnverifiedFor:  DefaultAuthorizationOidcRefreshTokenMaxUnverifiedFor,
				},
			},
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "invalid-disposal-policy", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
forceDisposeSessionOn: always`, expectedError: `[forceDisposeSessionOn] must be never or lostAccess`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "invalid-refresh-mode", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  mode: onDemand`, expectedError: `[mode] must be never or proactive`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "zero-percent", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  atLifetimePercent: 0`, expectedError: `[atLifetimePercent] must be between 1 and 99`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "percent-too-high", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  atLifetimePercent: 100`, expectedError: `[atLifetimePercent] must be between 1 and 99`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "zero-fallback", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  fallbackEvery: 0s`, expectedError: `[fallbackEvery] has to be positive`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "negative-fallback", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  fallbackEvery: -1m`, expectedError: `[fallbackEvery] has to be positive`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "zero-max-unverified", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  maxUnverifiedFor: 0s`, expectedError: `[maxUnverifiedFor] has to be positive`,
		},
		unmarshalYamlTestCase[AuthorizationOidcDeviceAuth]{
			name: "negative-max-unverified", yaml: `issuer: https://foo-bar
clientId: anId
clientSecret: aSecret
refreshToken:
  maxUnverifiedFor: -1m`, expectedError: `[maxUnverifiedFor] has to be positive`,
		},
	)
}

func TestAuthorizationOidc_RefreshEnabled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		dispose  string
		mode     string
		expected bool
	}{
		{"zero-value defaults", "", "", true},
		{"legacy opt-out", "never", "never", false},
		{"proactive", "never", "proactive", true},
		{"lost-access", "lostAccess", "never", true},
		{"both", "lostAccess", "proactive", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := AuthorizationOidcDeviceAuth{
				ForceDisposeSessionOn: tc.dispose,
				RefreshToken:          AuthorizationOidcRefreshToken{Mode: tc.mode},
			}
			assert.Equal(t, tc.expected, value.RefreshEnabled())
		})
	}
}

func TestAuthorizationOidc_RefreshTokenDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, dispose, mode string
		enabled                   bool
	}{
		{"omitted", "", "lostAccess", "proactive", true},
		{"empty object", "refreshToken: {}", "lostAccess", "proactive", true},
		{"explicit proactive", "refreshToken:\n  mode: proactive", "lostAccess", "proactive", true},
		{"proactive only", "forceDisposeSessionOn: never\nrefreshToken:\n  mode: proactive", "never", "proactive", true},
		{"lost access only", "refreshToken:\n  mode: never", "lostAccess", "never", true},
		{"legacy opt-out", "forceDisposeSessionOn: never\nrefreshToken:\n  mode: never", "never", "never", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var actual AuthorizationOidcDeviceAuth
			err := yaml.Unmarshal([]byte("issuer: https://foo-bar\nclientId: anId\nclientSecret: aSecret\n"+tc.yaml), &actual)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.dispose, actual.ForceDisposeSessionOn)
			assert.Equal(t, tc.mode, actual.RefreshToken.Mode)
			assert.Equal(t, tc.enabled, actual.RefreshEnabled())
			assert.Equal(t, uint8(70), actual.RefreshToken.AtLifetimePercent)
			assert.Equal(t, common.MustNewDuration("15m"), actual.RefreshToken.FallbackEvery)
			assert.Equal(t, common.MustNewDuration("30m"), actual.RefreshToken.MaxUnverifiedFor)
		})
	}
}

func TestAuthorizationOidc_IsEqualToRefreshSettings(t *testing.T) {
	value := AuthorizationOidcDeviceAuth{
		ForceDisposeSessionOn: "never",
		RefreshToken: AuthorizationOidcRefreshToken{
			Mode: "proactive", AtLifetimePercent: 70,
			FallbackEvery: common.MustNewDuration("15m"), MaxUnverifiedFor: common.MustNewDuration("30m"),
		},
	}
	assert.True(t, value.IsEqualTo(value))
	defaulted := AuthorizationOidcDeviceAuth{ForceDisposeSessionOn: "lostAccess", RefreshToken: AuthorizationOidcRefreshToken{
		Mode: "proactive", AtLifetimePercent: 70,
		FallbackEvery: common.MustNewDuration("15m"), MaxUnverifiedFor: common.MustNewDuration("30m"),
	}}
	assert.True(t, AuthorizationOidcDeviceAuth{}.IsEqualTo(defaulted))
	legacy := defaulted
	legacy.ForceDisposeSessionOn = "never"
	legacy.RefreshToken.Mode = "never"
	assert.False(t, AuthorizationOidcDeviceAuth{}.IsEqualTo(legacy))
	other := value
	other.ForceDisposeSessionOn = "lostAccess"
	assert.False(t, value.IsEqualTo(other))
	other = value
	other.RefreshToken.Mode = "never"
	assert.False(t, value.IsEqualTo(other))
	other = value
	other.RefreshToken.AtLifetimePercent = 71
	assert.False(t, value.IsEqualTo(other))
	other = value
	other.RefreshToken.FallbackEvery = common.MustNewDuration("10m")
	assert.False(t, value.IsEqualTo(other))
	other = value
	other.RefreshToken.MaxUnverifiedFor = common.MustNewDuration("20m")
	assert.False(t, value.IsEqualTo(other))
}
