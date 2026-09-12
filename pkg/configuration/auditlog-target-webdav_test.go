package configuration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	_ "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuditlogTargetWebdavYAML(t *testing.T) {
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte(`
name: archive
type: Web-DAV
endpoint: " https://dav.example.invalid/audit/ "
username: '{{ env "AUDIT_WEBDAV_USERNAME" }}'
password: '{{ env "AUDIT_WEBDAV_PASSWORD" }}'
`), &actual))
	expected := configuration.AuditlogTargetWebdav{
		Endpoint: "https://dav.example.invalid/audit/",
		Username: template.MustNewString("{{ env \"AUDIT_WEBDAV_USERNAME\" }}"),
		Password: template.MustNewString("{{ env \"AUDIT_WEBDAV_PASSWORD\" }}"),
	}
	require.Equal(t, configuration.AuditlogTargetName("archive"), actual.Name)
	require.True(t, expected.IsEqualTo(actual.V))

	encoded, err := yaml.Marshal(actual)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "type: webdav")
	var roundTripped configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, actual.IsEqualTo(roundTripped))
	require.Contains(t, configuration.GetSupportedAuditlogTargetFeatureFlags(), "webdav")
}

func TestAuditlogTargetWebdavAnonymousDefaults(t *testing.T) {
	var actual configuration.AuditlogTarget
	require.NoError(t, yaml.Unmarshal([]byte("name: archive\ntype: webdav\nendpoint: https://dav.example.invalid/audit\n"), &actual))
	conf := actual.V.(*configuration.AuditlogTargetWebdav)
	require.Equal(t, "https://dav.example.invalid/audit/", conf.Endpoint)
	values, err := conf.Render(nil)
	require.NoError(t, err)
	require.Empty(t, values.Username)
	require.Empty(t, values.Password)
}

func TestAuditlogTargetWebdavRendersCredentialsExactly(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "webdav-password")
	require.NoError(t, os.WriteFile(secretFile, []byte(" secret with spaces "), 0o600))
	conf := configuration.AuditlogTargetWebdav{
		Endpoint: "https://dav.example.invalid/",
		Username: template.MustNewString("archive-user"),
		Password: template.MustNewString("{{ file `" + secretFile + "` }}"),
	}

	values, err := conf.Render(nil)
	require.NoError(t, err)
	require.Equal(t, "archive-user", values.Username)
	require.Equal(t, " secret with spaces ", values.Password)
}

func TestAuditlogTargetWebdavEqualityIncludesAllFields(t *testing.T) {
	base := configuration.AuditlogTargetWebdav{
		Endpoint: "https://dav.example.invalid/audit/",
		Username: template.MustNewString("user"),
		Password: template.MustNewString("secret"),
	}
	tests := []struct {
		name   string
		change func(*configuration.AuditlogTargetWebdav)
	}{
		{"endpoint", func(value *configuration.AuditlogTargetWebdav) { value.Endpoint = "https://other.example.invalid/" }},
		{"username", func(value *configuration.AuditlogTargetWebdav) { value.Username = template.MustNewString("other") }},
		{"password", func(value *configuration.AuditlogTargetWebdav) { value.Password = template.MustNewString("other") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.change(&changed)
			require.False(t, base.IsEqualTo(changed))
		})
	}
}

func TestAuditlogTargetWebdavRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"missing-endpoint", "", "[endpoint] required"},
		{"http-endpoint", "endpoint: http://dav.example.invalid/audit", "absolute HTTPS"},
		{"endpoint-user", "endpoint: https://user@dav.example.invalid/audit", "user information"},
		{"endpoint-query", "endpoint: 'https://dav.example.invalid/audit?'", "query"},
		{"endpoint-fragment", "endpoint: 'https://dav.example.invalid/audit#'", "fragment"},
		{"endpoint-empty-port", "endpoint: 'https://dav.example.invalid:'", "empty port"},
		{"endpoint-invalid-port", "endpoint: 'https://dav.example.invalid:65536'", "invalid port"},
		{"endpoint-invalid-host", "endpoint: https://bad_host.example/audit", "invalid host"},
		{"endpoint-backslash", "endpoint: 'https://dav.example.invalid/audit\\other'", "path separator"},
		{"endpoint-empty-component", "endpoint: https://dav.example.invalid/audit//other", "empty or relative"},
		{"endpoint-leading-empty-component", "endpoint: https://dav.example.invalid//audit", "empty or relative"},
		{"endpoint-trailing-empty-component", "endpoint: https://dav.example.invalid/audit//", "empty or relative"},
		{"endpoint-relative-component", "endpoint: https://dav.example.invalid/audit/../other", "empty or relative"},
		{"endpoint-encoded-slash", "endpoint: https://dav.example.invalid/audit%2Fother", "encoded path separator"},
		{"endpoint-double-encoded-traversal", "endpoint: https://dav.example.invalid/audit/%252e%252e/other", "multiply encoded"},
		{"username-only", "endpoint: https://dav.example.invalid/audit\nusername: user", "both be configured"},
		{"password-only", "endpoint: https://dav.example.invalid/audit\npassword: secret", "both be configured"},
		{"unknown-field", "endpoint: https://dav.example.invalid/audit\ntoken: secret", "field token not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual configuration.AuditlogTarget
			err := yaml.Unmarshal([]byte("name: archive\ntype: webdav\n"+test.body+"\n"), &actual)
			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestAuditlogTargetWebdavRejectsInvalidRenderedCredentials(t *testing.T) {
	t.Setenv("EMPTY_WEBDAV_VALUE", "")
	tests := []struct {
		name     string
		username string
		password string
		expected string
	}{
		{"missing-username", "{{ env `EMPTY_WEBDAV_VALUE` }}", "secret", "[username] required"},
		{"missing-password", "user", "{{ env `EMPTY_WEBDAV_VALUE` }}", "[password] required"},
		{"colon-in-username", "domain:user", "secret", "must not contain a colon"},
		{"control-in-username", "user\nname", "secret", "control character"},
		{"control-in-password", "user", "secret\n", "[password] contains a control character"},
		{"render-failure", "{{ fail `cannot-load` }}", "secret", "[username] cannot render"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := configuration.AuditlogTargetWebdav{
				Endpoint: "https://dav.example.invalid/",
				Username: template.MustNewString(test.username),
				Password: template.MustNewString(test.password),
			}
			_, err := conf.Render(nil)
			require.ErrorContains(t, err, test.expected)
		})
	}
}

func TestAuditlogTargetWebdavAcceptsIPv6Endpoint(t *testing.T) {
	var actual configuration.AuditlogTarget
	err := yaml.Unmarshal([]byte("name: archive\ntype: webdav\nendpoint: https://[2001:db8::1]:9000/audit\n"), &actual)
	require.NoError(t, err)
}
