package configuration

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestTLSACMEPresenceControlsActivationForEveryConsumer(t *testing.T) {
	for _, consumer := range []string{"http", "monitoring"} {
		for _, named := range []bool{false, true} {
			for _, test := range []struct {
				definition string
				enabled    bool
			}{
				{"{}", false},
				{"{acme: null}", false},
				{"{<<: {acme: null}}", false},
				{"{<<: {acme: &off null}, acme: *off}", false},
				{"{acme: &off null, <<: {acme: {acceptTerms: true}}}", false},
				{"{acme: {acceptTerms: true}}", true},
				{"{<<: {acme: {acceptTerms: true}}}", true},
				{"{acme: {<<: {acceptTerms: true}}}", true},
			} {
				t.Run(consumer+"/"+test.definition, func(t *testing.T) {
					selection, root := test.definition, ""
					if named {
						selection = "public"
						root = "tls: {public: " + test.definition + "}\n"
					}
					root += consumer + ": {enabled: true, domains: [app.example.org], tls: " + selection + "}\n"
					if consumer == "monitoring" {
						root += "http: {enabled: acmeTlsAlpnOnly, domains: [validation.example.org], tls: {acme: {acceptTerms: true}}}\n"
					}
					var conf Configuration
					require.NoError(t, conf.LoadFromYaml(strings.NewReader(root+httpTestFlows), ""))
					tls := conf.Http.Tls
					if consumer == "monitoring" {
						tls = conf.Monitoring.Tls
					}
					definition, err := tls.ServerDefinition()
					require.NoError(t, err)
					require.Equal(t, test.enabled, definition.Acme.IsEnabled())
					if test.enabled {
						require.True(t, definition.Acme.AcceptTerms)
						require.Equal(t, DefaultHttpAcmeDirectoryUrl, definition.Acme.DirectoryUrl)
						source := consumer
						if named {
							source = filepath.Join("tls", "public")
						}
						require.Equal(t, filepath.Join(filepath.Dir(filepath.Dir(DefaultHttpAcmeStorage)), source, "acme"), definition.Acme.Storage)
						definition.Acme.Email = "copy@example.org"
						again, err := tls.ServerDefinition()
						require.NoError(t, err)
						require.Empty(t, again.Acme.Email, "effective definitions must own their ACME configuration")
					} else {
						require.Nil(t, definition.Acme)
						require.Len(t, definition.FileCertificates(), 1)
					}
					encoded, err := yaml.Marshal(conf)
					require.NoError(t, err)
					var restored Configuration
					require.NoError(t, yaml.Unmarshal(encoded, &restored))
					require.True(t, conf.IsEqualTo(restored))
				})
			}
		}
	}
}

func TestTLSACMERejectsMissingConsentAndRemovedEnabledForEveryDefinition(t *testing.T) {
	for _, automation := range []string{
		"{}", "{email: operator@example.org}", "{storage: account}", "{acceptTerms: false}",
		"{enabled: false}", "{enabled: true, acceptTerms: true}",
		"{<<: {enabled: false}, acceptTerms: true}",
		"false", "true", "[]", "''",
	} {
		for _, root := range []string{
			"tls: {unused: {acme: " + automation + "}}",
			"http: {tls: {acme: " + automation + "}}",
			"monitoring: {tls: {acme: " + automation + "}}",
		} {
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader(root+"\n"+httpTestFlows), ""), root)
		}
	}
}

func TestTLSACMEDefaultsAndNilOperations(t *testing.T) {
	var automation *TlsAcme
	require.False(t, automation.IsEnabled())
	require.NoError(t, automation.Trim())
	require.NoError(t, automation.Validate())
	var definition Tls
	require.NoError(t, definition.SetDefaults())
	require.Nil(t, definition.Acme)
	require.NoError(t, definition.Trim())
	require.True(t, definition.IsEqualTo(Tls{}))
	definition.Acme = &TlsAcme{}
	require.ErrorContains(t, definition.Validate(), "acceptTerms")
	require.False(t, definition.IsEqualTo(Tls{}))
}

func TestNamedTLSACMEMergesPreserveExplicitStorage(t *testing.T) {
	for _, definition := range []string{
		"{acme: {acceptTerms: true, storage: preserved/account}}",
		"{<<: {acme: {acceptTerms: true, storage: preserved/account}}}",
		"{acme: {<<: {acceptTerms: true, storage: preserved/account}}}",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader("tls: {unused: "+definition+"}\n"+httpTestFlows), ""))
		require.Equal(t, "preserved/account", conf.Tls["unused"].Acme.Storage)
	}
}
