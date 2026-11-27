package configuration

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHttpFileDefaultsDoNotChangeSourceSelection(t *testing.T) {
	var conf Http
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\ndomains: [app.example.org]\ntls: {}"), &conf))
	require.True(t, conf.Tls.IsEnabled())
	require.Equal(t, []HttpCertificate{{CertificateFile: DefaultHttpCertificateFile, PrivateKeyFile: DefaultHttpPrivateKeyFile}}, conf.Tls.FileCertificates())
	conf.Tls.Acme = &TlsAcme{AcceptTerms: true}
	require.Empty(t, conf.Tls.FileCertificates())
	conf.Tls.Certificates = []HttpCertificate{{CertificateFile: "chosen.crt", PrivateKeyFile: "chosen.key"}}
	require.Equal(t, conf.Tls.Certificates, conf.Tls.FileCertificates())
	conf.Tls.Certificates = nil
	conf.Tls.Acme, conf.Tls.Dummy = nil, true
	require.Empty(t, conf.Tls.FileCertificates())
}

func TestHttpProxyRequiresExplicitTrustAndTLSIsOptIn(t *testing.T) {
	for _, source := range []string{
		"enabled: true\ndomains: [app.example.org]\ntls: null",
		"tls: {enabled: false}",
		"tls: {enabled: true}",
		"upstream: {mode: reverseProxy}",
		"upstream: {mode: reverseProxy, trustedPeers: []}",
		"upstream: {mode: unknown}",
		"upstream: {trustedPeers: [private]}",
		"upstream: {mode: reverseProxy, trustedPeers: [localhost]}",
		"upstream: {mode: reverseProxy, trustedPeers: [private], defaultPort: 65536}",
		"upstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: /a/../b}",
		"upstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: //a}",
		"upstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: /a%2fb}",
		"upstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: /a/}",
		"upstream: {mode: reverseProxy, trustedPeers: [private]}\ntls: {enabled: false, dummy: true}",
	} {
		t.Run(source, func(t *testing.T) { var conf Http; require.Error(t, yaml.Unmarshal([]byte(source), &conf)) })
	}
	var conf Http
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\ndomains: [app.example.org]\nupstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: /team/bifroest, defaultPort: 8443}"), &conf))
	require.Nil(t, conf.Tls, "omitting TLS selects a plaintext backend only in explicit proxy mode")
	encoded, err := yaml.Marshal(conf)
	require.NoError(t, err)
	var restored Http
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, conf.IsEqualTo(restored))
	require.NoError(t, yaml.Unmarshal([]byte("upstream: {mode: reverseProxy, trustedPeers: [private]}\ntls: {}"), &conf))
	require.True(t, conf.Tls.IsEnabled())
	require.NoError(t, yaml.Unmarshal([]byte("upstream: {mode: reverseProxy, trustedPeers: [private]}"), &conf))
	require.Empty(t, conf.Tls.FileCertificates())
}

func TestHttpPrivatePeersAreNotAllSpecialOrLocalNetworks(t *testing.T) {
	peers := HttpTrustedPeers{"private"}
	for _, value := range []string{"10.1.2.3", "172.16.0.1", "192.168.2.3", "fd12::1", "::ffff:10.1.2.3"} {
		require.True(t, peers.Contains(netip.MustParseAddr(value)), value)
	}
	for _, value := range []string{"127.0.0.1", "::1", "169.254.1.2", "fe80::1", "100.64.1.2", "192.0.2.1", "2001:db8::1"} {
		require.False(t, peers.Contains(netip.MustParseAddr(value)), value)
	}
}

func TestOidcCodeProxyPrefixAndPortDefaults(t *testing.T) {
	for _, test := range []struct{ field, prefix string }{{"", "/bifroest"}, {"pathPrefix: '<default>'", "/bifroest"}, {"pathPrefix: ''", ""}, {"pathPrefix: /other", "/other"}} {
		var conf Configuration
		source := "http:\n  enabled: true\n  addresses: [':8080']\n  domains: [app.example.org]\n  upstream: {mode: reverseProxy, trustedPeers: [private], defaultPrefix: /bifroest, defaultPort: 8443}\nflows:\n- name: default\n  authorization:\n    type: oidcAuthorizationCode\n    issuer: https://idp.example.org\n    clientId: test\n    clientSecret: secret\n    " + test.field + "\n  environment: {type: local, name: test}\n"
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source), ""))
		code := conf.Flows[0].Authorization.V.(*AuthorizationOidcAuthorizationCode)
		require.Equal(t, "https://app.example.org:8443"+test.prefix+"/login/callback", code.RedirectURL())
		require.True(t, code.MatchesHttpOrigin("https://app.example.org:9443"), "browser requests use their validated public port")
		for _, origin := range []string{"http://app.example.org:9443", "https://evil.example.org:9443", "https://app.example.org:9443/path", "https://user@app.example.org:9443"} {
			require.False(t, code.MatchesHttpOrigin(origin), origin)
		}
	}
}
