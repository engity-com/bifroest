package configuration

import (
	"strings"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/template"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const codeConfiguration = `type: oidcAuthorizationCode
issuer: https://idp.example.org
clientId: client
clientSecret: secret
domain: app.example.org
`

func TestOidcCodeConfigurationRoundtripAndDefaults(t *testing.T) {
	var conf Authorization
	require.NoError(t, yaml.Unmarshal([]byte(codeConfiguration), &conf))
	code, ok := conf.V.(*AuthorizationOidcAuthorizationCode)
	require.True(t, ok)
	require.Equal(t, 2*time.Minute, code.LoginTimeout.Native())
	require.Equal(t, "app.example.org", code.Domain)
	require.Equal(t, "client", code.ClientId.String())
	require.Equal(t, "secret", code.ClientSecret.String())
	require.True(t, conf.SupportsRememberMe())
	raw, err := yaml.Marshal(conf)
	require.NoError(t, err)
	var restored Authorization
	require.NoError(t, yaml.Unmarshal(raw, &restored))
	require.True(t, conf.IsEqualTo(restored), string(raw))
}

func TestOidcSshLoginMessageConfigurationForBothGrants(t *testing.T) {
	for _, kind := range []string{"oidcAuthorizationCode", "oidcDeviceAuth"} {
		var conf Authorization
		raw := "type: " + kind + "\nissuer: https://idp.example.org\nclientId: client\nclientSecret: secret\nssh:\n  loginMessage: 'Code {{.code}}: {{.url}}'\n"
		require.NoError(t, yaml.Unmarshal([]byte(raw), &conf))
		require.Equal(t, template.MustNewString("Code {{.code}}: {{.url}}").String(), OidcSettings(conf.V).Ssh.LoginMessage.String())
		encoded, err := yaml.Marshal(conf)
		require.NoError(t, err)
		var restored Authorization
		require.NoError(t, yaml.Unmarshal(encoded, &restored))
		require.True(t, conf.IsEqualTo(restored))
		OidcSettings(restored.V).Ssh.LoginMessage = template.MustNewString("Other message")
		require.False(t, conf.IsEqualTo(restored))
		require.Error(t, yaml.Unmarshal([]byte(strings.ReplaceAll(raw, "Code {{.code}}: {{.url}}", "{{ broken template")), &conf))
		require.Error(t, yaml.Unmarshal([]byte(raw+"sshLoginMessage: obsolete\n"), &conf), "the old flat property must not remain as an alias")
		require.Error(t, yaml.Unmarshal([]byte(strings.ReplaceAll(raw, "  loginMessage:", "  unknown:")), &conf))
	}
}

func TestOidcCodeConfigurationRejectsUnsafeDomains(t *testing.T) {
	for _, domain := range []string{
		"http://app.example.org", "https://app.example.org",
		"user:secret@app.example.org", "app.example.org/callback",
		"app.example.org?next=evil", "app.example.org#fragment",
		"app.example.org:8443",
	} {
		t.Run(domain, func(t *testing.T) {
			var conf Authorization
			require.Error(t, yaml.Unmarshal([]byte(strings.ReplaceAll(codeConfiguration, "domain: app.example.org", "domain: "+domain)), &conf))
		})
	}
	for _, suffix := range []string{"loginTimeout: 0s\n", "loginTimeout: 11m\n", "unknown: true\n"} {
		var conf Authorization
		require.Error(t, yaml.Unmarshal([]byte(codeConfiguration+suffix), &conf))
	}
}

func TestOidcCodeRequiresConfiguredHTTPS(t *testing.T) {
	base := "authorizations:\n  corporate:\n" + indentCodeConfiguration(codeConfiguration) + "flows:\n  - name: work\n    http: {enabled: false}\n    authorization: corporate\n    environment: {type: dummy}\n"
	var conf Configuration
	require.Error(t, conf.LoadFromYaml(strings.NewReader(base), ""))
	withHTTP := "http:\n  enabled: true\n  domains: [app.example.org]\n  tls: {dummy: true}\n" + base
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(withHTTP), ""))
	require.Equal(t, "https://app.example.org/login/callback", conf.Flows[0].Authorization.V.(*AuthorizationOidcAuthorizationCode).RedirectURL())
	require.Error(t, conf.LoadFromYaml(strings.NewReader(strings.ReplaceAll(withHTTP, "domains: [app.example.org]", "domains: [other.example.org]")), ""))
}

func TestOidcCodeDomainDefaultsToFirstHTTPDomainAndCanSelectAnother(t *testing.T) {
	base := "http:\n  enabled: true\n  addresses: [':8443']\n  domains: [first.example.org, second.example.org]\n  tls: {dummy: true}\nauthorizations:\n  corporate:\n" + indentCodeConfiguration(strings.ReplaceAll(codeConfiguration, "domain: app.example.org\n", "")) + "flows:\n  - name: work\n    authorization: corporate\n    environment: {type: dummy}\n"
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(base), ""))
	code := conf.Flows[0].Authorization.V.(*AuthorizationOidcAuthorizationCode)
	require.Empty(t, code.Domain)
	require.Equal(t, "https://first.example.org:8443/login/callback", code.RedirectURL())
	selected := strings.ReplaceAll(base, "    type:", "    domain: SECOND.Example.org.\n    type:")
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(selected), ""))
	require.Equal(t, "https://second.example.org:8443/login/callback", conf.Flows[0].Authorization.V.(*AuthorizationOidcAuthorizationCode).RedirectURL())
	require.Error(t, conf.LoadFromYaml(strings.NewReader(strings.ReplaceAll(selected, "SECOND.Example.org.", "foreign.example.org")), ""))
}

func TestOidcCodeSensitiveDecodeErrorsAreRedacted(t *testing.T) {
	var conf Authorization
	err := yaml.Unmarshal([]byte(strings.ReplaceAll(codeConfiguration, "clientSecret: secret", "clientSecret: [DO-NOT-LEAK-THIS]")), &conf)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "DO-NOT-LEAK-THIS")
}

func indentCodeConfiguration(value string) string {
	return "    " + strings.ReplaceAll(strings.TrimSuffix(value, "\n"), "\n", "\n    ") + "\n"
}
