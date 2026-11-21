package configuration

import (
	"net"
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
	require.False(t, first.Tls.Enabled)
	require.NoError(t, first.Addresses[0].Set("127.0.0.1:9999"))
	require.True(t, second.Addresses[0].IsEqualTo(DefaultMonitoringAddresses[0]))
	require.NotEqual(t, first.Addresses[0].String(), second.Addresses[0].String())
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
		"enabled: null", "addresses: []\nenabled: true", "addresses: [null]", "addresses: ['127.0.0.1:9090','127.0.0.1:9090']", "tls: null", "tls: {enabled: true}",
		"tls: {acme: {enabled: true}}", "tls: {dummy: true}", "tls: {enabled: true, certificates: [{certificateFile: file}]}",
		"bearerToken: 'secret secret'", "bearerToken: abc\nbearerTokenFile: token", "readHeaderTimeout: 0s", "maxHeaderBytes: 0", "misspelled: true",
	} {
		t.Run(content, func(t *testing.T) { var conf Monitoring; require.Error(t, yaml.Unmarshal([]byte(content), &conf)) })
	}
	for _, content := range []string{"monitoring: null\n", "monitoring: false\n"} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(content+httpTestFlows), ""))
	}
	var conf Monitoring
	require.NoError(t, yaml.Unmarshal([]byte("enabled: true\nallowedRemoteHosts: ['::1']\ntls:\n  enabled: true\n  certificates:\n    - certificateFile: missing/certificate.pem\n      privateKeyFile: missing/private.pem\nbearerToken: abc_def-12=="), &conf))
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
