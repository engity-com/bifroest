package authorization

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
)

func TestAuthenticationCapabilitiesBuiltInMatrix(t *testing.T) {
	var entries crypto.Htpasswd
	require.NoError(t, entries.Set("alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="))
	// Deliberately only configure sources: discovery must not parse credentials
	// or validate/open these nonexistent files.
	ca := configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: "missing-ca"}
	simple := func(entry configuration.AuthorizationSimpleEntry, authority configuration.UserCertificateAuthorityProperties) *SimpleAuthorizer {
		return &SimpleAuthorizer{conf: &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{entry}, UserCertificateAuthorityProperties: authority}}
	}
	for _, test := range []struct {
		name     string
		provider AuthenticationCapabilityProvider
		named    AuthenticationCapabilities
		nameless AuthenticationCapabilities
	}{
		{name: "simple without entries", provider: &SimpleAuthorizer{conf: &configuration.AuthorizationSimple{}}},
		{name: "simple empty credentials", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice"}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{SessionPublicKey: true}},
		{name: "simple password only", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", Password: crypto.Password("plain:correct")}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, SessionPublicKey: true}},
		{name: "simple configured empty password", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", Password: crypto.Password("plain:")}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, SessionPublicKey: true}},
		{name: "simple password file", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", PasswordFile: "missing-password"}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, SessionPublicKey: true}},
		{name: "simple key only", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", AuthorizedKeys: "credential-not-inspected"}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true}},
		{name: "simple key file", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", AuthorizedKeysFile: "missing-keys"}, configuration.UserCertificateAuthorityProperties{}), named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true}},
		{name: "simple CA only", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice"}, ca), named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true, PublicKeyCertificateRequired: true}},
		{name: "simple CA and unknown key file", provider: simple(configuration.AuthorizationSimpleEntry{Name: "alice", AuthorizedKeysFile: "missing-keys"}, ca), named: AuthenticationCapabilities{PublicKey: true, SessionPublicKey: true}},
		{name: "simple CA without entries", provider: &SimpleAuthorizer{conf: &configuration.AuthorizationSimple{UserCertificateAuthorityProperties: ca}}},
		{name: "htpasswd no sources retains session path", provider: &HtpasswdAuthorizer{conf: &configuration.AuthorizationHtpasswd{}}, named: AuthenticationCapabilities{SessionPublicKey: true}},
		{name: "htpasswd entries", provider: &HtpasswdAuthorizer{conf: &configuration.AuthorizationHtpasswd{Entries: entries}}, named: AuthenticationCapabilities{Password: true, KeyboardInteractive: true, SessionPublicKey: true}},
		{name: "OIDC", provider: &OidcDeviceAuthAuthorizer{conf: &configuration.AuthorizationOidcDeviceAuth{}}, named: AuthenticationCapabilities{KeyboardInteractive: true, SessionPublicKey: true}, nameless: AuthenticationCapabilities{KeyboardInteractive: true, SessionPublicKey: true}},
		{name: "bifroest no CA", provider: &BifroestAuthorizer{conf: &configuration.AuthorizationBifroest{}}},
		{name: "bifroest certificate only", provider: &BifroestAuthorizer{conf: &configuration.AuthorizationBifroest{UserCertificateAuthorityProperties: ca}}, named: AuthenticationCapabilities{PublicKey: true, PublicKeyCertificateRequired: true}},
		{name: "none secretless", provider: &NoneAuthorizer{conf: &configuration.AuthorizationNone{}}, named: AuthenticationCapabilities{Secretless: true, SessionPublicKey: true}, nameless: AuthenticationCapabilities{Secretless: true, SessionPublicKey: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, transport := range []connection.Transport{connection.TransportHttp, connection.TransportSsh} {
				require.Equal(t, test.named, test.provider.AuthenticationCapabilities(DiscoveryInput{Transport: transport, RequestingName: true}))
				require.Equal(t, test.nameless, test.provider.AuthenticationCapabilities(DiscoveryInput{Transport: transport}))
			}
			for _, transport := range []connection.Transport{"", "unsupported"} {
				require.Equal(t, AuthenticationCapabilities{}, test.provider.AuthenticationCapabilities(DiscoveryInput{Transport: transport, RequestingName: true}))
			}
		})
	}
}

func TestAuthenticationCapabilitiesSimpleUnionsEntriesWithoutSelectingAUser(t *testing.T) {
	conf := &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{
		{Name: "password-user", Password: crypto.Password("plain:correct")},
		{Name: "key-user", AuthorizedKeysFile: "missing-keys"},
	}}
	authorizer := &SimpleAuthorizer{conf: conf}
	input := DiscoveryInput{Transport: connection.TransportHttp, RequestingName: true}
	expected := AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}
	require.Equal(t, expected, authorizer.AuthenticationCapabilities(input))
	conf.Entries[0].Name, conf.Entries[1].Name = "renamed-one", "renamed-two"
	require.Equal(t, expected, authorizer.AuthenticationCapabilities(input), "discovery must not select or disclose a particular username")
}

func TestAuthenticationCapabilitiesDoNotReadOrGenerateSimpleCredentialFiles(t *testing.T) {
	passwordPath := filepath.Join(t.TempDir(), "must-not-be-created")
	passwordType := crypto.PasswordTypePlain
	authorizer := &SimpleAuthorizer{conf: &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{
		Name: "alice", PasswordFile: crypto.PasswordFile(passwordPath), AuthorizedKeysFile: crypto.AuthorizedKeysFile(passwordPath), CreatePasswordFileIfAbsentOfType: &passwordType,
	}}, UserCertificateAuthorityProperties: configuration.UserCertificateAuthorityProperties{TrustedUserCAsFile: crypto.PublicKeysFile(passwordPath)}}}
	require.Equal(t, AuthenticationCapabilities{Password: true, KeyboardInteractive: true, PublicKey: true, SessionPublicKey: true}, authorizer.AuthenticationCapabilities(DiscoveryInput{Transport: connection.TransportHttp, RequestingName: true}))
	_, err := os.Stat(passwordPath)
	require.True(t, os.IsNotExist(err), "discovery must not invoke configuration validation or password generation")
}

func TestAuthenticationCapabilitiesHtpasswdDoesNotReloadOrCheckMembership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(path, []byte("alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n"), 0600))
	conf := &configuration.AuthorizationHtpasswd{}
	require.NoError(t, conf.File.Set(path))
	require.NoError(t, os.Remove(path))
	provider := &HtpasswdAuthorizer{conf: conf}
	input := DiscoveryInput{Transport: connection.TransportHttp, RequestingName: true}
	require.Equal(t, AuthenticationCapabilities{Password: true, KeyboardInteractive: true, SessionPublicKey: true}, provider.AuthenticationCapabilities(input))
	conf.File = crypto.HtpasswdFile{}
	require.Equal(t, AuthenticationCapabilities{SessionPublicKey: true}, provider.AuthenticationCapabilities(input), "use current loaded configuration, not the platform default path")
}

func TestAuthorizerFactoryRequiresCapabilitiesAndRejectsNil(t *testing.T) {
	// The public generic contract enforces providers at compile time. Exercise
	// the defensive reflection boundary against malformed internal registrations.
	configurationType := reflect.TypeFor[*configuration.AuthorizationNone]()
	original := configurationTypeToAuthorizerFactory[configurationType]
	t.Cleanup(func() { configurationTypeToAuthorizerFactory[configurationType] = original })
	for _, test := range []struct {
		name    string
		factory any
		error   string
	}{
		{"missing provider", func(context.Context, configuration.FlowName, *configuration.AuthorizationNone) (CloseableAuthorizer, error) {
			return &capabilityMissingTestAuthorizer{}, nil
		}, "does not provide authentication capabilities"},
		{"nil authorizer", func(context.Context, configuration.FlowName, *configuration.AuthorizationNone) (*NoneAuthorizer, error) {
			return nil, nil
		}, "factory returned nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configurationTypeToAuthorizerFactory[configurationType] = test.factory
			flow := selectionTestFlow("selected")
			var entry facaded
			require.ErrorContains(t, entry.newFrom(context.Background(), &flow), test.error)
		})
	}
}

type capabilityMissingTestAuthorizer struct{ CloseableAuthorizer }
