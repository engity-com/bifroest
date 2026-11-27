package configuration

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestMonitoringDefaultsAndIsolation(t *testing.T) {
	var absent, disabled Configuration
	require.NoError(t, absent.LoadFromYaml(strings.NewReader(httpTestFlows), ""))
	require.Nil(t, absent.Monitoring)
	require.False(t, absent.Monitoring.IsEnabled())
	require.NoError(t, disabled.LoadFromYaml(strings.NewReader("monitoring: {}\n"+httpTestFlows), ""))
	require.False(t, disabled.Monitoring.IsEnabled())
	require.True(t, absent.Ssh.IsEqualTo(disabled.Ssh))
	require.True(t, absent.Flows.IsEqualTo(disabled.Flows))
	var first, second Monitoring
	require.NoError(t, first.SetDefaults())
	require.NoError(t, second.SetDefaults())
	require.NoError(t, first.Validate())
	host, port, err := net.SplitHostPort(first.Addresses[0].String())
	require.NoError(t, err)
	require.True(t, net.ParseIP(host).IsLoopback())
	require.Equal(t, "9090", port)
	require.Empty(t, first.AllowedRemoteHosts)
	require.Empty(t, first.BearerToken)
	require.Nil(t, first.Tls)
	require.NoError(t, first.Addresses[0].Set("127.0.0.1:9999"))
	require.True(t, second.Addresses[0].IsEqualTo(DefaultMonitoringAddresses[0]))
	require.NotEqual(t, first.Addresses[0].String(), second.Addresses[0].String())
}

func TestMonitoringCertificatesRequireBothFilePaths(t *testing.T) {
	var conf Monitoring
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\ndomains: [monitoring.example.org]\ntls: {certificates: [{certificateFile: custom.crt, privateKeyFile: custom.key}]}"), &conf))
	require.Equal(t, []TlsCertificate{{CertificateFile: "custom.crt", PrivateKeyFile: "custom.key"}}, conf.Tls.Certificates)
	encoded, err := yaml.Marshal(conf)
	require.NoError(t, err)
	var restored Monitoring
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, conf.IsEqualTo(&restored))
	for _, source := range []string{
		"{}", "{certificateFile: custom.crt}", "{privateKeyFile: custom.key}",
		"{certificateFile: ''}", "{privateKeyFile: ''}", "{certificateFile: null}",
		"{privateKeyFile: false}", "{unknown: value}",
	} {
		var certificate TlsCertificate
		require.Error(t, yaml.Unmarshal([]byte(source), &certificate), source)
	}
}

func TestMonitoringTLSIsExplicitAndUsesTheSharedCertificateDefaults(t *testing.T) {
	for _, source := range []string{
		"monitoring: {enabled: true}",
		"tls: {unused: {dummy: true}}\nmonitoring: {enabled: true}",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		require.Nil(t, conf.Monitoring.Tls)
		require.False(t, conf.Monitoring.Tls.IsEnabled())
	}
	for _, source := range []string{
		"monitoring: {enabled: true, domains: [metrics.example.org], tls: {}}",
		"tls: {private: {}}\nmonitoring: {enabled: true, domains: [metrics.example.org], tls: private}",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		definition, err := conf.Monitoring.Tls.ServerDefinition()
		require.NoError(t, err)
		require.True(t, conf.Monitoring.Tls.IsEnabled())
		require.Equal(t, (&Tls{}).FileCertificates(), definition.Certificates)
		encoded, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var restored Configuration
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, conf.IsEqualTo(restored))
		require.True(t, restored.Monitoring.Tls.IsEnabled())
	}
}

func TestMonitoringTLSRequiresExplicitDomainsForInlineAndNamedDefinitions(t *testing.T) {
	for _, selection := range []string{"{}", "{dummy: true}", "{certificates: [{certificateFile: cert, privateKeyFile: key}]}", "private"} {
		for _, domains := range []string{"", "domains: [],", "domains: ['*.example.org'],", "domains: ['metrics.example.org:443'],"} {
			var conf Configuration
			source := "tls: {private: {dummy: true}}\nmonitoring: {enabled: true, " + domains + " tls: " + selection + "}\n"
			err := conf.LoadFromYaml(strings.NewReader(source+httpTestFlows), "")
			require.Error(t, err, source)
			if domains == "" || domains == "domains: []," {
				require.ErrorContains(t, err, "[domains]")
			}
		}
		var conf Configuration
		source := "tls: {private: {dummy: true}}\nmonitoring: {enabled: false, tls: " + selection + "}\n"
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+httpTestFlows), ""), "disabled monitoring must not require names or read files")
	}
}

func TestMonitoringInlineACMEStorageIsIsolatedAndPreservesExplicitPaths(t *testing.T) {
	const prefix = "http: {enabled: true, domains: [app.example.org], tls: {acme: {acceptTerms: true}}}\n"
	const enabled = "monitoring: {enabled: true, domains: [metrics.example.org], tls: "
	for _, test := range []struct{ definition, storage string }{
		{"{acme: {acceptTerms: true}}", filepath.Join(filepath.Dir(filepath.Dir(DefaultHttpAcmeStorage)), "monitoring", "acme")},
		{"{acme: {acceptTerms: true, storage: custom/account}}", "custom/account"},
		{"{<<: {acme: {acceptTerms: true, storage: merged/account}}}", "merged/account"},
		{"{acme: {<<: {acceptTerms: true, storage: nested/account}}}", "nested/account"},
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(prefix+enabled+test.definition+"}\n"+httpTestFlows), ""))
		require.NotEqual(t, conf.Http.Tls.Acme.Storage, conf.Monitoring.Tls.Acme.Storage)
		require.Equal(t, test.storage, conf.Monitoring.Tls.Acme.Storage)
		encoded, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var restored Configuration
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, conf.IsEqualTo(restored))
	}
}

func TestMonitoringEmptyPeerListsAndNetworks(t *testing.T) {
	for _, value := range []string{"null", "~", "", "[]", "''", "' '", "['', '  ', null]"} {
		t.Run(value, func(t *testing.T) {
			var conf Monitoring
			require.NoError(t, yaml.Unmarshal([]byte("enabled: true\nallowedRemoteHosts: "+value+"\n"), &conf))
			require.Empty(t, conf.AllowedRemoteHosts)
		})
	}
	var conf Monitoring
	require.NoError(t, yaml.Unmarshal([]byte("allowedRemoteHosts: ['192.0.2.1', '192.0.2.42/24', '::1', '2001:db8::/32', '::ffff:192.0.2.2']"), &conf))
	require.Len(t, conf.AllowedRemoteHosts, 5)
	for _, value := range []string{"[example.org]", "['10.0.0.1:9090']", "['192.0.2.1/33']", "['fe80::1%eth0']", "[true]", "[123]", "{}", "false"} {
		t.Run(value, func(t *testing.T) {
			var conf Monitoring
			require.Error(t, yaml.Unmarshal([]byte("allowedRemoteHosts: "+value), &conf))
		})
	}
}

func TestMonitoringConfigurationShapesAndTLS(t *testing.T) {
	for _, content := range []string{
		"enabled: null", "addresses: []\nenabled: true", "addresses: [null]", "addresses: ['127.0.0.1:9090','127.0.0.1:9090']", "tls: {enabled: true}",
		"tls: {acme: {}}", "tls: {certificates: [{certificateFile: file, privateKeyFile: ''}]}",
		"bearerToken: 'secret secret'", "bearerToken: abc\nbearerTokenFile: token", "readHeaderTimeout: 0s", "maxHeaderBytes: 0", "misspelled: true",
	} {
		t.Run(content, func(t *testing.T) { var conf Monitoring; require.Error(t, yaml.Unmarshal([]byte(content), &conf)) })
	}
	for _, content := range []string{"monitoring: null\n", "monitoring: false\n"} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(content+httpTestFlows), ""))
	}
	var conf Monitoring
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\ndomains: [monitoring.example.org]\nallowedRemoteHosts: ['::1']\ntls:\n  certificates:\n    - certificateFile: missing/certificate.pem\n      privateKeyFile: missing/private.pem\nbearerToken: abc_def-12=="), &conf))
	encoded, err := yaml.Marshal(conf)
	require.NoError(t, err)
	var decoded Monitoring
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))
	require.True(t, conf.IsEqualTo(&decoded))
	// YAML merges cannot bypass known-field, type or peer validation.
	for _, content := range []string{"<<: {unknown: true}", "<<: {enabled: null}", "<<: {allowedRemoteHosts: [not-an-ip]}"} {
		var target Monitoring
		require.Error(t, yaml.Unmarshal([]byte(content), &target))
	}
}
