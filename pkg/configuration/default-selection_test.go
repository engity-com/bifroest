package configuration

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTLSDefaultSelectionDistinguishesOmissionEmptyAndNull(t *testing.T) {
	for _, consumer := range []string{"http", "monitoring"} {
		for _, hasDefault := range []bool{false, true} {
			for _, test := range []struct {
				name, value string
				automatic   bool
				explicit    bool
			}{
				{name: "omitted", automatic: consumer == "http"},
				{name: "empty", value: "tls: ''", automatic: true},
				{name: "null", value: "tls: null"},
				{name: "default-name", value: "tls: default", explicit: true},
				{name: "inline", value: "tls: {dummy: true}", explicit: true},
				{name: "merged-empty", value: "<<: {tls: ''}", automatic: true},
				{name: "merged-null", value: "<<: {tls: null}"},
				{name: "null-overrides-default", value: "<<: {tls: default}, tls: null"},
				{name: "empty-overrides-null", value: "<<: {tls: null}, tls: ''", automatic: true},
				{name: "aliased-null", value: "<<: {tls: &off null}, tls: *off"},
			} {
				root := ""
				label := consumer + "/without-default/"
				if hasDefault {
					root = "tls: {default: {dummy: true}}\n"
					label = consumer + "/with-default/"
				}
				t.Run(label+test.name, func(t *testing.T) {
					settings := "enabled: true, domains: [app.example.org]"
					if consumer == "http" {
						// A plaintext backend is valid, so TLS selection itself is observable.
						settings += ", upstream: {mode: reverseProxy, trustedPeers: [127.0.0.1]}"
					}
					if test.value != "" {
						settings += ", " + test.value
					}
					var conf Configuration
					err := conf.LoadFromYaml(strings.NewReader(root+consumer+": {"+settings+"}\n"+httpTestFlows), "")
					if test.name == "default-name" && !hasDefault {
						require.ErrorContains(t, err, "unknown TLS definition")
						return
					}
					require.NoError(t, err)
					var selection *Tls
					if consumer == "http" {
						selection = conf.Http.Tls
					} else {
						selection = conf.Monitoring.Tls
					}
					require.Equal(t, test.explicit || test.automatic && hasDefault, selection.IsEnabled())
					if selection != nil {
						definition, err := selection.ServerDefinition()
						require.NoError(t, err)
						require.True(t, definition.Dummy)
					}
					encoded, err := yaml.Marshal(conf)
					require.NoError(t, err)
					var restored Configuration
					require.NoError(t, restored.LoadFromYaml(strings.NewReader(string(encoded)), ""), string(encoded))
					require.True(t, conf.IsEqualTo(restored))
					require.NoError(t, restored.Trim())
					require.True(t, conf.IsEqualTo(restored))
				})
			}
		}
	}
}

func TestHTTPDefaultTLSStillRequiresEncryptionInDirectMode(t *testing.T) {
	for _, selection := range []string{"", ", tls: ''", ", tls: null"} {
		for _, definition := range []string{"", "tls: {default: {dummy: true}}\n"} {
			var conf Configuration
			err := conf.LoadFromYaml(strings.NewReader(definition+"http: {enabled: true, domains: [app.example.org]"+selection+"}\n"+httpTestFlows), "")
			if definition != "" && selection != ", tls: null" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "[tls]")
			}
		}
	}
}

func TestExplicitNullFlowReferencesNeverSelectDefaults(t *testing.T) {
	for _, field := range []string{"environment", "authorization", "auditlog"} {
		for _, selection := range []string{
			field + ": null",
			"<<: {" + field + ": null}",
			"<<: {" + field + ": default}, " + field + ": null",
			"<<: {" + field + ": &off null}, " + field + ": *off",
		} {
			t.Run(selection, func(t *testing.T) {
				source := referenceTestDefaults + "auditlogs: {default: {}}\nflows: [{name: first, " + selection + "}]\n"
				var conf Configuration
				err := conf.LoadFromYaml(strings.NewReader(source), "")
				if field != "auditlog" {
					require.ErrorContains(t, err, "["+field+"] required but absent")
					return
				}
				require.NoError(t, err)
				require.Empty(t, conf.Flows[0].Auditlog)
				require.NoError(t, conf.Trim())
				require.Empty(t, conf.Flows[0].Auditlog)
				encoded, err := yaml.Marshal(conf)
				require.NoError(t, err)
				require.Contains(t, string(encoded), "auditlog: null")
				require.NotContains(t, string(encoded), "authorization: null")
				require.NotContains(t, string(encoded), "environment: null")
				var restored Configuration
				require.NoError(t, restored.LoadFromYaml(strings.NewReader(string(encoded)), ""))
				require.True(t, conf.IsEqualTo(restored))
				require.Empty(t, restored.Flows[0].Auditlog)
			})
		}
	}
}

func TestTLSAutomaticSelectionsFollowDefinitionChangesButNullDoesNot(t *testing.T) {
	for _, selection := range []string{"", ", tls: ''", ", tls: null"} {
		var conf Configuration
		source := "http: {enabled: true, domains: [app.example.org], upstream: {mode: reverseProxy, trustedPeers: [127.0.0.1]}" + selection + "}\n" +
			"monitoring: {enabled: true, domains: [metrics.example.org]" + selection + "}\n"
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+httpTestFlows), ""))
		require.Nil(t, conf.Http.Tls)
		require.Nil(t, conf.Monitoring.Tls)
		conf.Tls = TlsDefinitions{"default": {Dummy: true}}
		require.NoError(t, conf.Validate())
		require.Equal(t, selection != ", tls: null", conf.Http.Tls.IsEnabled())
		require.Equal(t, selection == ", tls: ''", conf.Monitoring.Tls.IsEnabled())
		delete(conf.Tls, "default")
		require.NoError(t, conf.Validate())
		require.Nil(t, conf.Http.Tls)
		require.Nil(t, conf.Monitoring.Tls)
	}
}

func TestSelectionEqualityPreservesExplicitOptOut(t *testing.T) {
	var automatic, disabled Configuration
	source := referenceTestDefaults + "auditlogs: {default: {}}\nflows: [{name: first%s}]\n" +
		"http: {upstream: {mode: reverseProxy, trustedPeers: [127.0.0.1]}%s}\n"
	// Root-less TLS defaults and explicit null still have different future behavior.
	require.NoError(t, automatic.LoadFromYaml(strings.NewReader(fmt.Sprintf(source, "", "")), ""))
	require.NoError(t, disabled.LoadFromYaml(strings.NewReader(fmt.Sprintf(source, ", auditlog: null", ", tls: null")), ""))
	require.False(t, automatic.Http.IsEqualTo(disabled.Http))
	require.False(t, automatic.Flows[0].IsEqualTo(disabled.Flows[0]))
}
