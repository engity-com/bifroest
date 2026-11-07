package configuration

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHttpDummyIsExplicitStrictAndRoundTrips(t *testing.T) {
	var defaults Http
	require.NoError(t, defaults.SetDefaults())
	require.False(t, defaults.Tls.Dummy)
	var original Configuration
	require.NoError(t, original.LoadFromYaml(strings.NewReader("http: {enabled: true, domains: [localhost, 127.0.0.1, '[::1]'], tls: {dummy: true}}\n"+httpTestFlows), ""))
	require.True(t, original.Http.Tls.Dummy)
	require.False(t, original.Http.Tls.Acme.Enabled)
	require.Empty(t, original.Http.Tls.Certificates)
	for _, value := range []any{*original.Http, original.Http} {
		encoded, err := yaml.Marshal(value)
		require.NoError(t, err)
		var restored Http
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, original.Http.IsEqualTo(restored))
	}
	other := original.Http.Tls
	other.Dummy = false
	require.False(t, original.Http.Tls.IsEqualTo(other))
	for _, source := range []string{
		`http: {enabled: true, domains: [localhost], tls: {dummy: false}}`,
		`http: {enabled: true, tls: {dummy: true}}`,
		`http: {tls: {dummy: "true"}}`, `http: {tls: {dummy: null}}`, `http: {tls: {dummy: 1}}`,
		`http: {tls: {dummy: true, certificates: [{certificateFile: a, privateKeyFile: b}]}}`,
		`http: {tls: {dummy: true, acme: {enabled: true, acceptTerms: true}}}`,
		`http: {tls: {<<: {dummy: "true"}}}`,
		"bad: &bad 'true'\nhttp: {tls: {dummy: *bad}}",
	} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), source)
	}
}
