package configuration

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
)

const httpTestFlows = `flows:
  - name: first
    authorization: {type: none}
    environment: {type: dummy}
`

const httpTestCertificate = `enabled: true
domains: [app.example.org]
tls:
  certificates:
    - certificateFile: missing/server.crt
      privateKeyFile: missing/server.key
`

func TestHttpConfigurationIsOptInAndPreservesSshDefaults(t *testing.T) {
	var absent, disabled Configuration
	require.NoError(t, absent.LoadFromYaml(strings.NewReader(httpTestFlows), ""))
	require.Nil(t, absent.Http)
	require.False(t, absent.Http.IsEnabled())
	require.NoError(t, disabled.LoadFromYaml(strings.NewReader("http: {}\n"+httpTestFlows), ""))
	require.NotNil(t, disabled.Http)
	require.False(t, disabled.Http.IsEnabled())
	require.True(t, absent.Ssh.IsEqualTo(disabled.Ssh))
	require.True(t, absent.Flows.IsEqualTo(disabled.Flows))
	require.NoError(t, absent.Http.Trim())
	require.NoError(t, absent.Http.Validate())
	require.True(t, absent.Http.IsEqualTo((*Http)(nil)))
	require.False(t, absent.Http.IsEqualTo(disabled.Http))
	require.False(t, disabled.Http.IsEqualTo((*Http)(nil)))
}

func TestHttpDefaultsAndDefaultSlicesAreIndependent(t *testing.T) {
	var first, second Http
	require.NoError(t, first.SetDefaults())
	require.NoError(t, second.SetDefaults())
	require.NoError(t, first.Validate())
	require.False(t, first.Enabled)
	require.Equal(t, ":443", first.Addresses[0].String())
	require.Empty(t, first.Domains)
	require.False(t, first.Tls.Acme.Enabled)
	require.False(t, first.Tls.Acme.AcceptTerms)
	require.Equal(t, DefaultHttpAcmeDirectoryUrl, first.Tls.Acme.DirectoryUrl)
	require.Equal(t, DefaultHttpAcmeStorage, first.Tls.Acme.Storage)
	require.True(t, filepath.IsAbs(first.Tls.Acme.Storage))
	require.Equal(t, 2*time.Minute, first.StartupTimeout.Native())
	require.Equal(t, 10*time.Second, first.ReadHeaderTimeout.Native())
	require.Equal(t, time.Minute, first.IdleTimeout.Native())
	require.Equal(t, 30*time.Second, first.GracefulShutdownTimeout.Native())
	require.Equal(t, 6*time.Hour, first.RememberMe.IdleTimeout.Native())
	require.Equal(t, uint32(1<<20), first.MaxHeaderBytes)
	require.NoError(t, first.Addresses[0].Set("127.0.0.1:8443"))
	require.Equal(t, ":443", second.Addresses[0].String())
	require.Equal(t, ":443", DefaultHttpAddresses[0].String())
}

func TestHttpCertificateConfigurationRoundTrip(t *testing.T) {
	var original Http
	require.NoError(t, yaml.Unmarshal([]byte(`enabled: true
addresses: ['127.0.0.1:8443', '[::1]:8443']
domains: [APP.EXAMPLE.ORG., bücher.example, 127.0.0.1, '[2001:0db8::1]']
tls:
  certificates:
    - certificateFile: ' C:\certs\server.pem '
      privateKeyFile: ' C:\certs\server-key.pem '
startupTimeout: 3m
readHeaderTimeout: 5s
idleTimeout: 45s
gracefulShutdownTimeout: 0s
maxHeaderBytes: 32768
rememberMe: {idleTimeout: 8h}
assetsDirectory: ' C:\web assets '
customCss: ['C:\web assets\custom.css']
customJs: ['C:\web assets\custom.js']
customHtmlHead: '<meta name="example" content="value">'
customHtmlBody: '<footer>Example</footer>'
`), &original))
	require.Equal(t, HttpDomains{"app.example.org", "xn--bcher-kva.example", "127.0.0.1", "[2001:db8::1]"}, original.Domains)
	require.Equal(t, `C:\certs\server.pem`, original.Tls.Certificates[0].CertificateFile)
	require.Equal(t, `C:\certs\server-key.pem`, original.Tls.Certificates[0].PrivateKeyFile)
	require.Equal(t, `C:\web assets`, original.AssetsDirectory)
	for _, value := range []any{original, &original} {
		encoded, err := yaml.Marshal(value)
		require.NoError(t, err)
		var restored Http
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, original.IsEqualTo(restored))
		require.Zero(t, restored.GracefulShutdownTimeout.Native(), "explicit zero must not turn back into the default")
	}
}

func TestHttpAcmeConfigurationIsExplicitAndMayCoexistWithCertificates(t *testing.T) {
	for _, certificates := range []string{"", "  certificates: [{certificateFile: server.pem, privateKeyFile: key.pem}]\n"} {
		var configured Http
		require.NoError(t, yaml.Unmarshal([]byte(`enabled: true
domains: [one.example.org, two.example.org]
tls:
`+certificates+`  acme:
    enabled: true
    acceptTerms: true
    email: operator@example.org
    directoryUrl: https://acme-staging-v02.api.letsencrypt.org/directory
    storage: custom/acme
`), &configured))
		require.True(t, configured.Tls.Acme.Enabled)
		encoded, err := yaml.Marshal(configured)
		require.NoError(t, err)
		var restored Http
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, configured.IsEqualTo(restored))
	}
}

func TestDisabledHttpRoundTripPreservesExplicitEmptySourcesAndZeroGrace(t *testing.T) {
	var configured Http
	require.NoError(t, yaml.Unmarshal([]byte("addresses: []\ntls: {acme: {directoryUrl: '', storage: ''}}\ngracefulShutdownTimeout: 0s\n"), &configured))
	encoded, err := yaml.Marshal(configured)
	require.NoError(t, err)
	var restored Http
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, configured.IsEqualTo(restored))
}

func TestHttpEnabledRequiresDomainsListenerAndTlsSource(t *testing.T) {
	for _, test := range []struct{ source, message string }{
		{"enabled: true", "[domains]"},
		{"enabled: true\ndomains: [app.example.org]", "[tls]"},
		{strings.Replace(httpTestCertificate, "enabled: true", "enabled: true\naddresses: []", 1), "[addresses]"},
		{strings.Replace(httpTestCertificate, "domains: [app.example.org]", "domains: []", 1), "[domains]"},
	} {
		var configured Http
		require.ErrorContains(t, yaml.Unmarshal([]byte(test.source), &configured), test.message)
	}
}

func TestHttpRejectsUnknownNullOrMistypedPropertiesIncludingAliasesAndMerges(t *testing.T) {
	for _, source := range []string{
		"http: null", "http: false", "http: []", "http: {enabled: null}", "http: {enabled: 'true'}", "http: {enable: true}",
		"http: {domains: null}", "http: {addresses: null}", "http: {tls: null}", "http: {tls: {acme: null}}",
		"http: {tls: {certificate: []}}", "http: {tls: {certificates: null}}", "http: {tls: {certificates: [null]}}",
		"http: {tls: {certificates: [{certificateFile: cert.pem, privateKeyFile: null}]}}",
		"http: {tls: {certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem, key: other}]}}",
		"http: {tls: {acme: {enabled: yes}}}", "http: {tls: {acme: {acceptTerms: null}}}", "http: {tls: {acme: {acceptTerm: true}}}",
		"http: {rememberMe: null}", "http: {rememberMe: {idleTimeout: null}}", "http: {rememberMe: {timeout: 6h}}",
		"http: {startupTimeout: null}", "http: {startupTimeout: 1}", "http: {maxHeaderBytes: '1234'}",
		"http: {customCss: null}", "http: {customJs: path.js}", "http: {customJs: [null]}", "http: {customHtmlHead: false}",
		"unused: &nothing null\nhttp: *nothing", "unused: &nothing null\nhttp: {enabled: *nothing}",
		"<<: {http: null}", "http: {<<: {enabled: null}}", "http: {tls: {acme: {<<: {unknown: true}}}}",
	} {
		t.Run(source, func(t *testing.T) {
			var conf Configuration
			require.Error(t, conf.LoadFromYaml(strings.NewReader(source+"\n"+httpTestFlows), ""))
		})
	}
	var configured Configuration
	require.NoError(t, configured.LoadFromYaml(strings.NewReader("off: &off false\n<<: {http: {enabled: *off}}\n"+httpTestFlows), ""))
	require.NotNil(t, configured.Http)
	require.False(t, configured.Http.IsEnabled())
}

func TestHttpRejectsUnsafeLimitsAndNonLocalAssetPaths(t *testing.T) {
	for _, source := range []string{
		"startupTimeout: 0s", "startupTimeout: -1s", "readHeaderTimeout: 0s", "readHeaderTimeout: -1s", "idleTimeout: 0s", "idleTimeout: -1s",
		"gracefulShutdownTimeout: -1s", "maxHeaderBytes: 0", "maxHeaderBytes: 16777217", "maxHeaderBytes: -1",
		"rememberMe: {idleTimeout: 0s}", "rememberMe: {idleTimeout: -1s}", "rememberMe: {idleTimeout: invalid}",
		"addresses: ['']", "addresses: [null]", "addresses: [':443', ':443']", "addresses: [':65536']",
		"assetsDirectory: https://example.org", "customJs: ['']", "customCss: ['   ']", "customCss: [https://example.org/custom.css]",
	} {
		t.Run(source, func(t *testing.T) {
			var configured Http
			require.Error(t, yaml.Unmarshal([]byte(source), &configured))
		})
	}
}

func TestHttpAcmeRejectsImplicitConsentAndInvalidMetadata(t *testing.T) {
	for _, source := range []string{
		"enabled: true", "enabled: true\nacceptTerms: false", "enabled: true\nacceptTerms: true\nstorage: ''",
		"directoryUrl: http://ca.example/directory", "directoryUrl: /directory", "directoryUrl: https://user:password@ca.example/directory",
		"directoryUrl: https://ca.example/directory?token=secret", "directoryUrl: https://ca.example/directory?", "directoryUrl: https://ca.example/directory#fragment",
		"directoryUrl: https://*.example/directory", "email: not-an-address", "email: 'Operator <operator@example.org>'",
	} {
		t.Run(source, func(t *testing.T) {
			var configured HttpAcme
			err := yaml.Unmarshal([]byte(source), &configured)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "password@")
			require.NotContains(t, err.Error(), "token=secret")
		})
	}
}

func TestHttpPrivateKeyConfigurationErrorsDoNotExposeRejectedValues(t *testing.T) {
	const secret = "private-material-do-not-log"
	for _, value := range []string{"[" + secret + "]", "{value: " + secret + "}", `"` + secret + `\u0000"`, `"-----BEGIN PRIVATE KEY-----\n` + secret + `\n-----END PRIVATE KEY-----"`} {
		var configured Http
		err := yaml.Unmarshal([]byte("tls: {certificates: [{certificateFile: cert.pem, privateKeyFile: "+value+"}]}"), &configured)
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
	}
}

func TestHttpConfigurationValidationDoesNotReadOrCreateFiles(t *testing.T) {
	storage := filepath.Join(t.TempDir(), "not-created")
	var configured Http
	require.NoError(t, configured.SetDefaults())
	configured.Enabled = true
	configured.Domains = HttpDomains{"app.example.org"}
	configured.Tls.Certificates = []HttpCertificate{{CertificateFile: filepath.Join(storage, "server.pem"), PrivateKeyFile: filepath.Join(storage, "key.pem")}}
	configured.Tls.Acme.Enabled, configured.Tls.Acme.AcceptTerms = true, true
	configured.Tls.Acme.Storage = filepath.Join(storage, "acme")
	configured.AssetsDirectory = filepath.Join(storage, "assets")
	configured.CustomJs = HttpAssetFiles{filepath.Join(storage, "custom.js")}
	require.NoError(t, configured.Validate())
	_, err := os.Stat(storage)
	require.True(t, os.IsNotExist(err))
}

func TestConfigurationHttpDiscoveryChecksOnlyEnabledEndpointDomains(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(httpTestFlows), ""))
	conf.Flows[0].DiscoverAsSlug = "foo"
	second := conf.Flows[0]
	second.Name = "second"
	second.Requirement.Http.IncludedHost = common.MustNewRegexp(`^other\.example\.org$`)
	conf.Flows = append(conf.Flows, second)
	require.NoError(t, conf.Validate(), "HTTP is absent")
	conf.Http = &Http{}
	require.NoError(t, conf.Http.SetDefaults())
	conf.Http.Domains = HttpDomains{"app.example.org"}
	conf.Http.Tls.Certificates = []HttpCertificate{{CertificateFile: "cert.pem", PrivateKeyFile: "key.pem"}}
	conf.Http.Enabled = true
	require.NoError(t, conf.Validate(), "other host is not an endpoint domain")
	conf.Http.Domains = append(conf.Http.Domains, "other.example.org")
	require.ErrorContains(t, conf.Validate(), "same slug")
	conf.Http.Enabled = false
	require.NoError(t, conf.Validate(), "disabled HTTP must not change legacy SSH startup")
	conf.Http.Enabled = true
	no := false
	conf.Flows[1].Http.Enabled = &no
	require.NoError(t, conf.Validate(), "HTTP-disabled publishers do not collide")
}

func TestConfigurationHttpLoadIsTransactional(t *testing.T) {
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader("http: {domains: [app.example.org]}\n"+httpTestFlows), ""))
	previous := conf
	require.Error(t, conf.LoadFromYaml(strings.NewReader("http: {enabled: 'true'}\n"+httpTestFlows), ""))
	require.True(t, previous.IsEqualTo(conf))
}

func TestConfigurationHttpDiscoveryCollisionFailsConfigurationLoading(t *testing.T) {
	var conf Configuration
	err := conf.LoadFromYaml(strings.NewReader(`http:
  enabled: true
  domains: [APP.EXAMPLE.ORG.]
  tls:
    certificates: [{certificateFile: cert.pem, privateKeyFile: key.pem}]
flows:
  - name: first
    discoverAsSlug: foo
    requirement: {includedRequestingName: '^alice$'}
    authorization: {type: none}
    environment: {type: dummy}
  - name: second
    discoverAsSlug: foo
    requirement: {includedRequestingName: '^bob$'}
    authorization: {type: none}
    environment: {type: dummy}
`), "collision.yaml")
	require.ErrorContains(t, err, "[http][domains]")
	require.ErrorContains(t, err, "same slug")
}

func TestHttpReferenceExamplesParseWithoutFilesystemOrNetworkAccess(t *testing.T) {
	contents, err := os.ReadFile("../../docs/reference/connection/http.md")
	require.NoError(t, err)
	examples := regexp.MustCompile("(?s)```yaml\n(.*?)\n```").FindAllSubmatch(contents, -1)
	require.Len(t, examples, 2)
	for _, example := range examples {
		var conf Configuration
		require.NoError(t, conf.LoadFromYaml(strings.NewReader(string(example[1])), "http-reference-example"))
		require.True(t, conf.Http.IsEnabled())
	}
}
