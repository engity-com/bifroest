package authorization

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
)

type httpCodeMetadataTestAuthorizer struct {
	httpLoginDescriptionTestAuthorizer
	code *configuration.AuthorizationOidcAuthorizationCode
}

func (this *httpCodeMetadataTestAuthorizer) CodeConfiguration() *configuration.AuthorizationOidcAuthorizationCode {
	return this.code
}

func httpCodeMetadataConfiguration(t *testing.T, reverseProxy bool) *configuration.AuthorizationOidcAuthorizationCode {
	t.Helper()
	source := `http:
  enabled: true
  addresses: [':8443']
  domains: [app.example.org]
  tls: {dummy: true}
`
	if reverseProxy {
		source += `  upstream:
    mode: reverseProxy
    trustedPeers: [10.20.0.0/24]
`
	}
	source += `flows:
  - name: work
    authorization:
      type: oidcAuthorizationCode
      issuer: https://issuer.example.org
      clientId: example-client
      clientSecret: example-only
    environment: {type: dummy}
`
	var conf configuration.Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), "<http-origin-test>"))
	return conf.Flows[0].Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
}

func TestHttpCodeOriginEligibilityWorksWithoutConcreteNetworkAuthorizers(t *testing.T) {
	code := httpCodeMetadataConfiguration(t, false)
	all := AuthenticationCapabilities{Password: true, KeyboardInteractive: true, OidcAuthorizationCode: true, PublicKey: true, Secretless: true, SessionPublicKey: true}
	for _, origin := range []string{"https://app.example.org:8443", "https://app.example.org", "https://app.example.org:443", "https://app.example.org:8444", "https://second.example.org:8443", "", "https://APP.EXAMPLE.ORG:8443"} {
		for _, named := range []bool{false, true} {
			adapter := &httpCodeMetadataTestAuthorizer{httpLoginDescriptionTestAuthorizer: httpLoginDescriptionTestAuthorizer{capabilities: all}, code: code}
			entry := facaded{CloseableAuthorizer: adapter, capabilityProvider: adapter}
			expected := all
			expected.OidcAuthorizationCode = origin == code.Origin()
			require.Equal(t, expected, entry.httpLoginCapabilities(origin, named))
			require.Equal(t, []DiscoveryInput{{Transport: connection.TransportHttp, RequestingName: named}}, adapter.inputs)
			native := &OidcDeviceAuthAuthorizer{conf: &code.AuthorizationOidcDeviceAuth, code: code}
			require.Equal(t, expected.OidcAuthorizationCode, native.matchesCodeOrigin(origin))
			nativeEntry := facaded{CloseableAuthorizer: native, capabilityProvider: native}
			nativeExpected := native.AuthenticationCapabilities(DiscoveryInput{Transport: connection.TransportHttp, RequestingName: named})
			nativeExpected.OidcAuthorizationCode = expected.OidcAuthorizationCode
			require.Equal(t, nativeExpected, nativeEntry.httpLoginCapabilities(origin, named))
		}
	}
	adapter := &httpCodeMetadataTestAuthorizer{httpLoginDescriptionTestAuthorizer: httpLoginDescriptionTestAuthorizer{capabilities: all}}
	entry := facaded{CloseableAuthorizer: adapter, capabilityProvider: adapter}
	require.Equal(t, all, entry.httpLoginCapabilities("https://other.example", true), "nil code metadata must not alter unrelated providers")
	adapter.code = code
	adapter.capabilities.OidcAuthorizationCode = false
	require.False(t, entry.httpLoginCapabilities(code.Origin(), true).OidcAuthorizationCode, "a matching origin must not grant an absent capability")
}

func TestHttpProxyCodeOriginEligibilityUsesSharedPureMatcher(t *testing.T) {
	code := httpCodeMetadataConfiguration(t, true)
	all := AuthenticationCapabilities{OidcAuthorizationCode: true, PublicKey: true}
	for _, test := range []struct {
		origin  string
		allowed bool
	}{
		{"https://app.example.org", true},
		{"https://app.example.org:8443", true},
		{"https://app.example.org:8444", true},
		{"https://app.example.org:443", false},
		{"https://second.example.org", false},
		{"http://app.example.org", false},
		{"https://APP.EXAMPLE.ORG", false},
		{"https://user@app.example.org", false},
		{"https://app.example.org/path", false},
		{"", false},
	} {
		for _, named := range []bool{false, true} {
			adapter := &httpCodeMetadataTestAuthorizer{httpLoginDescriptionTestAuthorizer: httpLoginDescriptionTestAuthorizer{capabilities: all}, code: code}
			entry := facaded{CloseableAuthorizer: adapter, capabilityProvider: adapter}
			expected := all
			expected.OidcAuthorizationCode = test.allowed
			require.Equal(t, expected, entry.httpLoginCapabilities(test.origin, named), test.origin)
			native := &OidcDeviceAuthAuthorizer{conf: &code.AuthorizationOidcDeviceAuth, code: code}
			require.Equal(t, test.allowed, native.matchesCodeOrigin(test.origin), test.origin)
		}
	}
	require.False(t, matchesOidcCodeOrigin(nil, "https://app.example.org"))
}

func TestPureOidcCapabilitiesKeepGrantAndTransportSemantics(t *testing.T) {
	conf := new(configuration.AuthorizationOidcDeviceAuth)
	for _, code := range []bool{false, true} {
		for _, transport := range []connection.Transport{connection.TransportSsh, connection.TransportHttp, "", "other"} {
			for _, named := range []bool{false, true} {
				input := DiscoveryInput{Transport: transport, RequestingName: named}
				expected := AuthenticationCapabilities{}
				if input.supported() {
					expected = AuthenticationCapabilities{KeyboardInteractive: !code || transport == connection.TransportSsh, OidcAuthorizationCode: code, SessionPublicKey: true}
				}
				require.Equal(t, expected, OidcAuthenticationCapabilities(conf, code, input))
				require.Equal(t, AuthenticationCapabilities{}, OidcAuthenticationCapabilities(nil, code, input))
			}
		}
	}
	var authorizer *OidcDeviceAuthAuthorizer
	require.Equal(t, AuthenticationCapabilities{}, authorizer.AuthenticationCapabilities(DiscoveryInput{Transport: connection.TransportHttp}))
}
