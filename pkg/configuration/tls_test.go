package configuration

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const sharedTlsTestYaml = `tls:
  public:
    minVersion: "1.3"
    certificates: [{certificateFile: missing/cert.pem, privateKeyFile: missing/key.pem}]
    acme: {acceptTerms: true, storage: preserved/account}
http: {enabled: true, addresses: [":8443"], domains: [app.example.org], tls: public}
monitoring: {enabled: true, domains: [metrics.example.net], tls: public}
`

func TestTLSProfilesResolveWithoutIOAndRoundTripAsReferences(t *testing.T) {
	var original Configuration
	require.NoError(t, original.LoadFromYaml(strings.NewReader(sharedTlsTestYaml+httpTestFlows), ""))
	httpProfile, err := original.Http.Tls.ServerDefinition()
	require.NoError(t, err)
	monitorProfile, err := original.Monitoring.Tls.ServerDefinition()
	require.NoError(t, err)
	require.True(t, httpProfile.IsEqualTo(monitorProfile))
	require.Equal(t, "preserved/account", httpProfile.Acme.Storage)
	httpProfile.Certificates[0].PrivateKeyFile = "changed"
	unchanged, err := original.Monitoring.Tls.ServerDefinition()
	require.NoError(t, err)
	require.Equal(t, "missing/key.pem", unchanged.Certificates[0].PrivateKeyFile)
	encoded, err := yaml.Marshal(original)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "tls: public")
	var restored Configuration
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, original.IsEqualTo(restored))
	require.NoError(t, restored.Validate())
	restored.Http.Tls.Reference = "missing"
	require.ErrorContains(t, restored.Validate(), "unknown TLS definition")
}

func TestTLSProfilesRejectUnknownMistypedAndAmbiguousConfiguration(t *testing.T) {
	for _, source := range []string{
		"tls: null", "tls: []", "tls: {one: two}", "tls: {one: null}",
		"tls: {one: {dummy: true, acme: {acceptTerms: true}}}",
		"tls: {one: {minVersion: '1.1'}}",
		"tls: {one: {certificates: [null]}}",
		"tls: {one: {}, one: {}}", "http: {tls: missing}", "http: {tls: 123}", "monitoring: {tls: false}",
		"tlsChallenge: null", "tlsChallenge: {addresses: []}", "tlsChallenge: {addresses: [':443', ':443']}",
	} {
		t.Run(source, func(t *testing.T) {
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		})
	}
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(sharedTlsTestYaml+httpTestFlows), ""))
	conf.Http.Tls.Dummy = true
	require.ErrorContains(t, conf.Validate(), "cannot be combined")
	conf.Http.Tls.Dummy = false
	conf.Monitoring.Tls.Certificates = []TlsCertificate{{CertificateFile: "cert", PrivateKeyFile: "key"}}
	require.ErrorContains(t, conf.Validate(), "cannot be combined")
}

func TestSharedTLSDefinitionsAcceptTheUsingListenersDomains(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(sharedTlsTestYaml+httpTestFlows), ""))
	for _, name := range []string{"metrics.example.net", "deep.one.example.org", "127.0.0.1", "[::1]"} {
		conf.Monitoring.Domains = ServerNames{name}
		require.NoError(t, conf.Validate(), name)
		http, err := conf.Http.Tls.ServerDefinition()
		require.NoError(t, err)
		monitoring, err := conf.Monitoring.Tls.ServerDefinition()
		require.NoError(t, err)
		require.True(t, http.IsEqualTo(monitoring))
		require.Equal(t, HttpDomains{"app.example.org"}, conf.Http.Domains)
	}
	conf.Monitoring.Domains = nil
	require.ErrorContains(t, conf.Validate(), "[domains]")
	conf.Monitoring.Enabled = false
	require.NoError(t, conf.Validate())
	for _, name := range []string{"*.example.org", "app.example.org:443", "https://app.example.org"} {
		conf.Http.Domains = HttpDomains{name}
		require.ErrorContains(t, conf.Validate(), "[domains]")
	}
}

func TestTLSAllowedNamesIsNotAConfigurationProperty(t *testing.T) {
	for _, definition := range []string{
		"{allowedNames: []}",
		"{allowedNames: [app.example.org]}",
		"{<<: {allowedNames: [app.example.org]}}",
	} {
		for _, source := range []string{
			"tls: {public: " + definition + "}",
			"http: {tls: " + definition + "}",
			"monitoring: {tls: " + definition + "}",
		} {
			var conf Configuration
			require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), "allowedNames")
		}
	}
}

func TestTLSProfileDefaultStoresAreIsolatedAndMonitoringRemainsOptIn(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`tls:
  first:
    acme: {acceptTerms: true}
  second:
    acme: {acceptTerms: true}
monitoring: {enabled: true}
`+httpTestFlows), ""))
	require.NotEqual(t, conf.Tls["first"].Acme.Storage, conf.Tls["second"].Acme.Storage)
	require.Equal(t, filepath.Join(filepath.Dir(filepath.Dir(DefaultHttpAcmeStorage)), "tls", "first", "acme"), conf.Tls["first"].Acme.Storage)
	require.False(t, conf.Monitoring.Tls.IsEnabled())
}

func TestActiveACMERequiresTheHTTPTransportForValidation(t *testing.T) {
	const definition = "tls: {public: {acme: {acceptTerms: true}}}\n"
	const monitoring = "monitoring: {enabled: true, domains: [metrics.example.org], tls: public}\n"
	for _, http := range []string{
		"",
		"http: {}\n",
		"http: {enabled: false}\n",
		"http: {enabled: true, domains: [app.example.org], upstream: {mode: reverseProxy, trustedPeers: [127.0.0.1]}}\n",
	} {
		var conf Configuration
		require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(definition+monitoring+http+httpTestFlows), ""), "[http] active ACME requires a TLS listener")
	}
	for _, http := range []string{
		"http: {enabled: true, addresses: [':8443'], domains: [app.example.org], tls: {certificates: [{certificateFile: custom.crt, privateKeyFile: custom.key}]}}\n",
		"http: {enabled: true, addresses: [':8443'], domains: [app.example.org], tls: public}\n",
		"http: {enabled: acmeTlsAlpnOnly, addresses: [':8443'], domains: [app.example.org], tls: public}\n",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(definition+monitoring+http+httpTestFlows), ""))
	}
	// Neither an unused definition nor disabled monitoring opens validation sockets.
	for _, source := range []string{
		"",
		"monitoring: {enabled: false, domains: [metrics.example.org], tls: public}\n",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(definition+source+httpTestFlows), ""))
	}
}

func TestTLSChallengeIsNotAConfigurationProperty(t *testing.T) {
	for _, source := range []string{
		"tlsChallenge: {}",
		"tlsChallenge: {addresses: [':8443']}",
		"<<: {tlsChallenge: {addresses: [':8443']}}",
	} {
		var conf Configuration
		require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), "tlsChallenge")
	}
}

func TestTLSProfileNamesCannotAliasPortableDefaultStores(t *testing.T) {
	for _, name := range []string{"", ".", "..", "public.", "public ", "a/b", `a\b`, "CON", "con.pem", "LPT1", "COM9", "public:one", "a?b"} {
		require.Error(t, validateTlsName(name), name)
	}
	for _, name := range []string{"public", "Private-files", "monitoring.internal", "private_files"} {
		require.NoError(t, validateTlsName(name), name)
	}
	profile := Tls{Certificates: []TlsCertificate{{CertificateFile: "cert", PrivateKeyFile: "key"}}}
	require.ErrorContains(t, (TlsDefinitions{"public": profile, "PUBLIC": profile}).Validate(), "ignoring case")
}

func TestListenersInlineAndNamedTLSUseExactlyTheSameDefinition(t *testing.T) {
	for _, consumer := range []string{"http", "monitoring"} {
		t.Run(consumer, func(t *testing.T) {
			for _, definition := range []string{
				`{dummy: true, minVersion: "1.3", reloadInterval: 7s}`,
				`{certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem}], acme: null}`,
				`{certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem}], acme: {acceptTerms: true, email: operator@example.org, storage: preserved/account}}`,
				`{acme: {acceptTerms: true, storage: preserved/account}}`,
				`{minVersion: "1.2", acme: {acceptTerms: true, storage: preserved/account}}`,
			} {
				t.Run(definition, func(t *testing.T) {
					var value map[string]any
					require.NoError(t, yaml.Unmarshal([]byte(definition), &value))
					load := func(named bool) Configuration {
						t.Helper()
						listener := map[string]any{
							"enabled": true, "domains": []string{"app.example.org"}, "tls": value,
							"upstream": map[string]any{"mode": "reverseProxy", "trustedPeers": []string{"127.0.0.1/8"}},
						}
						root := map[string]any{consumer: listener}
						if consumer == "monitoring" {
							delete(listener, "upstream")
							root["http"] = map[string]any{"enabled": true, "domains": []string{"validation.example.org"}, "tls": map[string]any{"dummy": true}}
						}
						if named {
							listener["tls"] = "public"
							root["tls"] = map[string]any{"public": value}
						}
						raw, err := yaml.Marshal(root)
						require.NoError(t, err)
						var conf Configuration
						require.NoError(t, conf.LoadFromYaml(strings.NewReader(string(raw)+httpTestFlows), ""))
						return conf
					}
					inline, named := load(false), load(true)
					inlineSelection, namedSelection := inline.Http.Tls, named.Http.Tls
					if consumer == "monitoring" {
						inlineSelection, namedSelection = inline.Monitoring.Tls, named.Monitoring.Tls
					}
					inlineTLS, err := inlineSelection.ServerDefinition()
					require.NoError(t, err)
					namedTLS, err := namedSelection.ServerDefinition()
					require.NoError(t, err)
					require.True(t, inlineTLS.IsEqualTo(namedTLS))
					require.Equal(t, inlineSelection.IsEnabled(), namedSelection.IsEnabled())
					encoded, err := yaml.Marshal(named)
					require.NoError(t, err)
					require.Contains(t, string(encoded), "tls: public")
					var restored Configuration
					require.NoError(t, yaml.Unmarshal(encoded, &restored))
					require.True(t, named.IsEqualTo(restored))
				})
			}
		})
	}
}

func TestListenersInlineAndNamedTLSRejectTheSameInvalidDefinitions(t *testing.T) {
	for _, definition := range []string{
		`{dummy: true, certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem}]}`,
		`{dummy: true, acme: {acceptTerms: true}}`,
		`{enabled: false, dummy: true}`,
		`{minVersion: "1.1", dummy: true}`,
		`{unknown: true}`,
	} {
		t.Run(definition, func(t *testing.T) {
			for _, source := range []string{
				"http: {enabled: true, domains: [app.example.org], tls: " + definition + "}\n",
				"tls: {public: " + definition + "}\nhttp: {enabled: true, domains: [app.example.org], tls: public}\n",
				"monitoring: {enabled: true, domains: [metrics.example.org], tls: " + definition + "}\n",
				"tls: {public: " + definition + "}\nmonitoring: {enabled: true, domains: [metrics.example.org], tls: public}\n",
			} {
				var conf Configuration
				require.Error(t, conf.LoadFromYaml(strings.NewReader(source+httpTestFlows), ""))
			}
		})
	}
}

func TestNamedDummyTLSIsExplicitAndUnusedDefinitionsPerformNoIO(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(`tls:
  testing: {dummy: true}
  unused: {minVersion: "1.3"}
http:
  enabled: true
  domains: [localhost]
  tls: testing
`+httpTestFlows), ""))
	definition, err := conf.Http.Tls.ServerDefinition()
	require.NoError(t, err)
	require.True(t, definition.Dummy)
	require.Empty(t, definition.FileCertificates())
	require.Nil(t, definition.Acme)
	require.Contains(t, conf.Tls, "unused")
	require.NoError(t, conf.Validate())
}

func TestNamedTLSDefinitionsCannotContainReferencesInGo(t *testing.T) {
	require.ErrorContains(t, (TlsDefinitions{"invalid": {Reference: "another"}}).Validate(), "not a reference")
}

func TestTLSMinimumVersionDefaultsTo13(t *testing.T) {
	for _, source := range []string{"{}", `minVersion: "1.3"`, `minVersion: "1.2"`} {
		t.Run(source, func(t *testing.T) {
			var definition Tls
			require.NoError(t, yaml.Unmarshal([]byte(source), &definition))
			expected := uint16(tls.VersionTLS13)
			if definition.MinVersion == "1.2" {
				expected = tls.VersionTLS12
			}
			require.Equal(t, expected, definition.MinimumVersion())
		})
	}
}

func TestTLSCertificatesRequireBothFilePathsInEveryDefinition(t *testing.T) {
	for _, test := range []struct{ pair, missing string }{
		{"{}", "certificateFile"},
		{"{certificateFile: custom.crt}", "privateKeyFile"},
		{"{privateKeyFile: custom.key}", "certificateFile"},
		{"{certificateFile: ' ', privateKeyFile: custom.key}", "certificateFile"},
		{"{certificateFile: custom.crt, privateKeyFile: ' '}", "privateKeyFile"},
	} {
		t.Run(test.pair, func(t *testing.T) {
			var pair TlsCertificate
			require.ErrorContains(t, yaml.Unmarshal([]byte(test.pair), &pair), test.missing)
			for _, source := range []string{
				"http: {tls: {certificates: [" + test.pair + "]}}",
				"tls: {public: {certificates: [" + test.pair + "]}}",
				"tls: {public: {certificates: [" + test.pair + "], acme: {acceptTerms: true}}}",
				"monitoring: {tls: {certificates: [" + test.pair + "]}}",
			} {
				var conf Configuration
				require.ErrorContains(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), test.missing)
			}
		})
	}
	var definition Tls
	require.ErrorContains(t, yaml.Unmarshal([]byte("certificates: [{certificateFile: custom.crt}, {privateKeyFile: custom.key}]"), &definition), "privateKeyFile")
}

func TestTLSDefaultCertificateSetIsSelectedOnlyWithoutOtherSources(t *testing.T) {
	defaults := []TlsCertificate{{CertificateFile: DefaultHttpCertificateFile, PrivateKeyFile: DefaultHttpPrivateKeyFile}}
	for _, test := range []struct {
		source string
		want   []TlsCertificate
	}{
		{"{}", defaults},
		{"certificates: []", defaults},
		{"acme: null", defaults},
		{"dummy: true", nil},
		{"acme: {acceptTerms: true}", nil},
		{"certificates: [{certificateFile: custom.crt, privateKeyFile: custom.key}]", []TlsCertificate{{CertificateFile: "custom.crt", PrivateKeyFile: "custom.key"}}},
	} {
		t.Run(test.source, func(t *testing.T) {
			var definition Tls
			require.NoError(t, yaml.Unmarshal([]byte(test.source), &definition))
			require.Equal(t, test.want, definition.FileCertificates())
		})
	}
}

func TestTLSWithoutDefaultRequiresAnExplicitListenerDefinitionOrReference(t *testing.T) {
	for _, source := range []string{
		"tls: {other: {dummy: true}}\nhttp: {}",
		"http: {enabled: true, domains: [app.example.org], upstream: {mode: reverseProxy, trustedPeers: [127.0.0.1]}}",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		require.Nil(t, conf.Http.Tls)
		require.False(t, conf.Http.Tls.IsEnabled())
		require.Empty(t, conf.Http.Tls.FileCertificates())
		_, err := conf.Http.Tls.ServerDefinition()
		require.ErrorContains(t, err, "not configured")
		encoded, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var restored Configuration
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.Nil(t, restored.Http.Tls, "serialization must not introduce an empty TLS definition")
		require.True(t, conf.IsEqualTo(restored))
	}
	for _, source := range []string{
		"http: {enabled: true, domains: [app.example.org], tls: {}}",
		"tls: {public: {}}\nhttp: {enabled: true, domains: [app.example.org], tls: public}",
		"http: {<<: {enabled: true, domains: [app.example.org], tls: {}}}",
	} {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		require.True(t, conf.Http.Tls.IsEnabled())
		definition, err := conf.Http.Tls.ServerDefinition()
		require.NoError(t, err)
		require.Equal(t, uint16(tls.VersionTLS13), definition.MinimumVersion())
		require.Equal(t, []TlsCertificate{{CertificateFile: DefaultHttpCertificateFile, PrivateKeyFile: DefaultHttpPrivateKeyFile}}, definition.Certificates)
		encoded, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var restored Configuration
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, restored.Http.Tls.IsEnabled(), "an explicit empty TLS definition must survive serialization")
		require.True(t, conf.IsEqualTo(restored))
	}
	for _, source := range []string{
		"http: {enabled: true, domains: [app.example.org]}",
		"tls: {default: {dummy: true}}\nhttp: {enabled: true, domains: [app.example.org], tls: null}",
		"http: {tls: {enabled: true}}", "http: {tls: {enabled: false}}",
		"tls: {unused: {enabled: true}}", "tls: {unused: {enabled: false}}",
		"monitoring: {tls: {enabled: true, certificates: [{}]}}",
		"monitoring: {tls: {enabled: false}}",
	} {
		var conf Configuration
		require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""), source)
	}
}

func TestTLSReferenceExamplesParseWithoutIO(t *testing.T) {
	contents, err := os.ReadFile("../../docs/reference/transports/tls/index.md")
	require.NoError(t, err)
	sections := strings.SplitN(string(contents), "## Examples\n", 2)
	require.Len(t, sections, 2)
	examples := regexp.MustCompile("(?s)```yaml\n(.*?)\n```").FindAllStringSubmatch(sections[1], -1)
	require.Len(t, examples, 5)
	for index, example := range examples {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(example[1]+"\n"+httpTestFlows), "tls-reference-example"))
		if index == 4 {
			require.NotNil(t, conf.Http)
			require.False(t, conf.Http.IsEnabled())
			require.True(t, conf.Http.IsAcmeTlsAlpnOnly())
			require.NotNil(t, conf.Http.Tls)
			require.True(t, conf.Monitoring.Tls.IsEnabled())
			definition, err := conf.Monitoring.Tls.ServerDefinition()
			require.NoError(t, err)
			require.True(t, definition.Acme.IsEnabled())
			require.Equal(t, ":8443", conf.Http.Addresses[0].String())
		}
	}
}

func TestTLSReferenceDefaultCertificateExamplesSupplyCompletePairs(t *testing.T) {
	contents, err := os.ReadFile("../../docs/reference/transports/tls/index.md")
	require.NoError(t, err)
	property := strings.SplitN(string(contents), `<<property("certificates",`, 2)[1]
	property = strings.SplitN(property, `<<property("dummy",`, 2)[0]
	examples := regexp.MustCompile("(?s)```yaml\n(.*?)\n```").FindAllStringSubmatch(property, -1)
	require.Len(t, examples, 3)
	for _, example := range examples {
		var definition Tls
		require.NoError(t, yaml.Unmarshal([]byte(example[1]), &definition))
		require.Len(t, definition.Certificates, 1)
		require.NotEmpty(t, definition.Certificates[0].CertificateFile)
		require.NotEmpty(t, definition.Certificates[0].PrivateKeyFile)
		require.Equal(t, definition.Certificates, definition.FileCertificates())
	}
}
