package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHttpModeStrictlyDecodesAndRoundTripsBooleansAndAlpnOnly(t *testing.T) {
	for _, test := range []struct {
		source string
		mode   HttpMode
	}{
		{"false", HttpDisabled},
		{"true", HttpEnabled},
		{"acmeTlsAlpnOnly", HttpAcmeTlsAlpnOnly},
	} {
		t.Run(test.source, func(t *testing.T) {
			var mode HttpMode
			require.NoError(t, yaml.Unmarshal([]byte(test.source), &mode))
			require.Equal(t, test.mode, mode)
			encoded, err := yaml.Marshal(mode)
			require.NoError(t, err)
			require.Equal(t, test.source+"\n", string(encoded))
			var restored HttpMode
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.Equal(t, mode, restored)
			http := &Http{Enabled: mode}
			require.Equal(t, mode == HttpEnabled, http.IsEnabled())
			require.Equal(t, mode != HttpDisabled, http.IsListenerEnabled())
			require.Equal(t, mode == HttpAcmeTlsAlpnOnly, http.IsAcmeTlsAlpnOnly())
		})
	}
	for _, source := range []string{"'true'", "'false'", "yes", "off", "0", "1", "unknown", "ACMETLSALPNONLY", "[]", "{}"} {
		var mode HttpMode
		require.Error(t, yaml.Unmarshal([]byte(source), &mode), source)
	}
	var http *Http
	require.False(t, http.IsEnabled())
	require.False(t, http.IsListenerEnabled())
	require.False(t, http.IsAcmeTlsAlpnOnly())
	_, err := yaml.Marshal(HttpMode(255))
	require.Error(t, err)
}

func TestHttpAlpnOnlyAcceptsInlineAndNamedAcmeWithoutIO(t *testing.T) {
	for _, source := range []string{
		"http: {enabled: acmeTlsAlpnOnly, addresses: [':8443'], domains: [app.example.org], tls: {acme: {acceptTerms: true}}}",
		"tls: {public: {acme: {acceptTerms: true}}}\nhttp: {enabled: acmeTlsAlpnOnly, addresses: [':8443'], domains: [app.example.org], tls: public}",
		"http: {<<: {enabled: acmeTlsAlpnOnly, domains: [app.example.org], tls: {acme: {acceptTerms: true}}}}",
	} {
		t.Run(source, func(t *testing.T) {
			var conf Configuration
			require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
			require.False(t, conf.Http.IsEnabled())
			require.True(t, conf.Http.IsListenerEnabled())
			require.True(t, conf.Http.IsAcmeTlsAlpnOnly())
			encoded, err := yaml.Marshal(conf)
			require.NoError(t, err)
			require.Contains(t, string(encoded), "enabled: acmeTlsAlpnOnly")
			var restored Configuration
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, conf.IsEqualTo(restored))
		})
	}
}

func TestHttpAlpnOnlyRejectsIncompleteUnsafeAndConflictingSettings(t *testing.T) {
	for _, fields := range []string{
		"domains: [app.example.org]",
		"domains: [app.example.org], tls: {}",
		"domains: [app.example.org], tls: {dummy: true}",
		"domains: [app.example.org], tls: {certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem}]}",
		"tls: {acme: {acceptTerms: true}}",
		"domains: [app.example.org], addresses: [], tls: {acme: {acceptTerms: true}}",
		"domains: [app.example.org], upstream: {mode: reverseProxy, trustedPeers: [private]}, tls: {acme: {acceptTerms: true}}",
	} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader("http: {enabled: acmeTlsAlpnOnly, "+fields+"}\n"+httpTestFlows), ""), fields)
	}
	for _, source := range []string{
		"tls: {public: {dummy: true}}\nhttp: {enabled: acmeTlsAlpnOnly, domains: [app.example.org], tls: public}",
		"http: {enabled: acmeTlsAlpnOnly, domains: [app.example.org], tls: {acme: {acceptTerms: true}}}\ntlsChallenge: {addresses: [':8443']}",
		"http: {enabled: null}",
		"http: {enabled: 'false'}",
	} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), source)
	}
}

func TestHttpAlpnOnlyDoesNotEnableOidcAuthorizationCodeEndpoints(t *testing.T) {
	var conf Configuration
	require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(`http:
  enabled: acmeTlsAlpnOnly
  domains: [app.example.org]
  tls: {acme: {acceptTerms: true}}
flows:
  - name: login
    authorization:
      type: oidcAuthorizationCode
      issuer: https://idp.example.org
      clientId: client
      clientSecret: secret
    environment: {type: dummy}
`), ""), "requires enabled HTTPS")
}
