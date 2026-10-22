package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestHttpDomainsRejectWildcardsAuthoritiesAndCanonicalDuplicates(t *testing.T) {
	for _, source := range []string{
		"['']", "[' app.example.org']", "['app.example.org ']", "['*.example.org']", "[https://example.org]", "[example.org/path]",
		"[example.org:443]", "['[::1]:443']", "['::1']", "[user@example.org]", "[example..org]", "[null]", "[1234]",
		"[app.example.org, APP.EXAMPLE.ORG.]", "[bücher.example, xn--bcher-kva.example]", "['[2001:0db8::1]', '[2001:db8::1]']",
	} {
		t.Run(source, func(t *testing.T) {
			var domains HttpDomains
			require.Error(t, yaml.Unmarshal([]byte(source), &domains))
		})
	}
}

func TestHttpDomainsCanonicalizeForHostAllowlistWithoutImplicitWildcard(t *testing.T) {
	var domains HttpDomains
	require.NoError(t, yaml.Unmarshal([]byte("[APP.EXAMPLE.ORG., bücher.example, 127.0.0.1, '[2001:0db8::1]']"), &domains))
	for _, host := range []string{"app.example.org", "APP.EXAMPLE.ORG.:443", "bücher.example:8443", "xn--bcher-kva.example", "127.0.0.1:443", "[2001:db8::1]:443"} {
		allowed, err := domains.AllowsHost(host)
		require.NoError(t, err)
		require.True(t, allowed, host)
	}
	for _, host := range []string{"other.example.org", "sub.app.example.org", "example.org", "app.example.org.attacker.example"} {
		allowed, err := domains.AllowsHost(host)
		require.NoError(t, err)
		require.False(t, allowed, host)
	}
	allowed, err := domains.AllowsHost("app.example.org/path")
	require.Error(t, err)
	require.False(t, allowed)
	allowed, err = (HttpDomains{}).AllowsHost("app.example.org")
	require.NoError(t, err)
	require.False(t, allowed)
}
