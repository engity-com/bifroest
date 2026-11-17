//go:build unix || windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestAuthenticationCapabilitiesLocalMatrixWithoutNativeAuthentication(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*configuration.AuthorizationLocal)
		named     AuthenticationCapabilities
		nameless  AuthenticationCapabilities
	}{
		{name: "repository defaults", named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}},
		{name: "key only", configure: func(c *configuration.AuthorizationLocal) {
			c.Password.Allowed, c.Password.InteractiveAllowed = template.BoolOf(false), template.BoolOf(false)
		}, named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true}},
		{name: "password and interactive independent", configure: func(c *configuration.AuthorizationLocal) {
			c.Password.Allowed = template.BoolOf(false)
		}, named: AuthenticationCapabilities{KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}},
		{name: "interactive can be disabled alone", configure: func(c *configuration.AuthorizationLocal) {
			c.Password.InteractiveAllowed = template.BoolOf(false)
		}, named: AuthenticationCapabilities{Password: true, PublicKey: true, SessionPublicKey: true}},
		{name: "keys disabled", configure: func(c *configuration.AuthorizationLocal) {
			c.AuthorizedKeys = nil
		}, named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true}},
		{name: "CA only", configure: func(c *configuration.AuthorizationLocal) {
			c.AuthorizedKeys = nil
			c.TrustedUserCAsFile = "missing-ca"
		}, named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true, PublicKeyCertificateRequired: true}},
		{name: "CA with unknown keys file", configure: func(c *configuration.AuthorizationLocal) {
			c.TrustedUserCAs = crypto.PublicKeys("credential-not-inspected")
			c.AuthorizedKeys = template.MustNewStrings("{{ fail `must not render authorizedKeys` }}")
		}, named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}},
		{name: "dynamic password rules stay possible", configure: func(c *configuration.AuthorizationLocal) {
			c.Password.Allowed = template.MustNewBool("{{ fail `must not execute password rule` }}")
			c.Password.InteractiveAllowed = template.MustNewBool("{{ fail `must not execute interactive rule` }}")
		}, named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}},
		{name: "empty allowed does not enable methods", configure: func(c *configuration.AuthorizationLocal) {
			c.Password = configuration.PasswordProperties{EmptyAllowed: template.BoolOf(true)}
		}, named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true}},
		{name: "configured PAM uses build availability", configure: func(c *configuration.AuthorizationLocal) {
			c.PamService = "must-not-start-PAM"
		}, named: AuthenticationCapabilities{Password: localPamAuthenticationAvailable, KeyboardInteractive: localPamAuthenticationAvailable, PublicKey: true, SessionPublicKey: true}, nameless: AuthenticationCapabilities{KeyboardInteractive: localPamAuthenticationAvailable}},
		{name: "PAM interactive disabled for nameless input", configure: func(c *configuration.AuthorizationLocal) {
			c.PamService = "must-not-start-PAM"
			c.Password.InteractiveAllowed = template.BoolOf(false)
		}, named: AuthenticationCapabilities{Password: localPamAuthenticationAvailable, PublicKey: true, SessionPublicKey: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := &configuration.AuthorizationLocal{}
			require.NoError(t, conf.SetDefaults())
			conf.PamService = "" // Exercise repository paths independently of the build default.
			if test.configure != nil {
				test.configure(conf)
			}
			// No user repository, native account or loaded CA is available here.
			provider := &LocalAuthorizer{conf: conf}
			for _, transport := range []connection.Transport{connection.TransportHttp, connection.TransportSsh} {
				require.Equal(t, test.named, provider.AuthenticationCapabilities(DiscoveryInput{Transport: transport, RequestingName: true}))
				require.Equal(t, test.nameless, provider.AuthenticationCapabilities(DiscoveryInput{Transport: transport}))
			}
			require.Equal(t, AuthenticationCapabilities{}, provider.AuthenticationCapabilities(DiscoveryInput{Transport: "unknown", RequestingName: true}))
		})
	}
}

func TestDiscoveryBoolPossibleNeverExecutesDynamicTemplates(t *testing.T) {
	for _, plain := range []string{"false", "disabled", "0", "no", "off", "", "<nil>", "nil", "null", " FALSE "} {
		require.False(t, discoveryBoolPossible(template.MustNewBool(plain)), plain)
	}
	for _, plain := range []string{"true", "enabled", "1", "yes", "on", " TRUE "} {
		require.True(t, discoveryBoolPossible(template.MustNewBool(plain)), plain)
	}
	require.False(t, discoveryBoolPossible(template.Bool{}))
	// The first expression would be false if executed; the second would fail.
	// Both must remain unknown/possible without any template execution.
	require.True(t, discoveryBoolPossible(template.MustNewBool("{{ false }}")))
	require.True(t, discoveryBoolPossible(template.MustNewBool("{{ fail `must not execute` }}")))
}
