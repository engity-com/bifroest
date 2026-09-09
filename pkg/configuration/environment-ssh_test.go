package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func environmentSshKnownHost(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	return "target.example.org " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestEnvironmentSshDefaults(t *testing.T) {
	var environment Environment
	require.NoError(t, yaml.Unmarshal([]byte(`
type: ssh
address: target.example.org:22
user: alice
acceptAllHostKeys: true
`), &environment))

	actual, ok := environment.V.(*EnvironmentSsh)
	require.True(t, ok)
	require.Equal(t, 10*time.Second, mustRenderDuration(t, actual.ConnectTimeout))
	require.True(t, mustRenderBool(t, actual.LoginAllowed))
	require.True(t, mustRenderBool(t, actual.PortForwardingAllowed))
	require.Empty(t, actual.IdentityFiles)
	require.Equal(t, sys.OsLinux, actual.Os)
}

func TestEnvironmentSshTargetOs(t *testing.T) {
	var environment Environment
	require.NoError(t, yaml.Unmarshal([]byte(`
type: ssh
address: target.example.org:22
user: alice
os: windows
acceptAllHostKeys: true
`), &environment))

	actual := environment.V.(*EnvironmentSsh)
	require.Equal(t, sys.OsWindows, actual.Os)
}

func TestEnvironmentVariablesBelongToEnvironment(t *testing.T) {
	var environment Environment
	require.NoError(t, yaml.Unmarshal([]byte(`
type: ssh
address: target.example.org:22
user: alice
acceptAllHostKeys: true
variables:
  TARGET_NAME: production
`), &environment))

	require.Equal(t, template.MustNewString("production"), environment.Variables["TARGET_NAME"])
	marshaled, err := yaml.Marshal(environment)
	require.NoError(t, err)
	require.Contains(t, string(marshaled), "variables:")
	require.Contains(t, string(marshaled), "TARGET_NAME: production")
}

func TestEnvironmentSshHostKeyValidationMatrix(t *testing.T) {
	knownHost := environmentSshKnownHost(t)
	for _, test := range []struct {
		name    string
		extra   string
		wantErr bool
	}{
		{name: "missing", wantErr: true},
		{name: "known-hosts", extra: "knownHosts: " + strings.TrimSpace(knownHost)},
		{name: "accept-all", extra: "acceptAllHostKeys: true"},
		{name: "conflicting", extra: "acceptAllHostKeys: true\nknownHosts: " + strings.TrimSpace(knownHost), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var environment Environment
			err := yaml.Unmarshal([]byte("type: ssh\naddress: target.example.org:22\nuser: alice\n"+test.extra+"\n"), &environment)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEnvironmentSshRejectsInvalidStaticValues(t *testing.T) {
	for _, test := range []struct {
		name string
		yaml string
	}{
		{name: "address", yaml: "address: missing-port\nuser: alice"},
		{name: "empty-address-host", yaml: "address: :22\nuser: alice"},
		{name: "user", yaml: "address: target.example.org:22\nuser: ''"},
		{name: "identity", yaml: "address: target.example.org:22\nuser: alice\nidentityFiles: ['']"},
		{name: "timeout", yaml: "address: target.example.org:22\nuser: alice\nconnectTimeout: -1s"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var environment Environment
			require.Error(t, yaml.Unmarshal([]byte("type: ssh\nacceptAllHostKeys: true\n"+test.yaml+"\n"), &environment))
		})
	}
}

func TestEnvironmentSshCertificateConfiguration(t *testing.T) {
	var environment Environment
	require.NoError(t, yaml.Unmarshal([]byte(`
type: ssh
address: target.example.org:22
user: '{{ .session.created.remote.user }}'
acceptAllHostKeys: true
certificate:
  identityFile: /var/lib/bifroest/target-key
  authorityIdentityFile: /etc/bifroest/user-ca
  validity: 24h
  principals:
    - '{{ .session.created.remote.user }}'
  extensions:
    permit-pty: ""
    role@example.org: production
`), &environment))

	actual := environment.V.(*EnvironmentSsh)
	require.NotNil(t, actual.Certificate)
	require.Equal(t, 24*time.Hour, mustRenderDuration(t, actual.Certificate.Validity))
	require.Equal(t, 30*time.Second, mustRenderDuration(t, actual.Certificate.ValidAfterSkew))
	require.Equal(t, template.MustNewString("production"), actual.Certificate.Extensions["role@example.org"])

	roundtrip, err := yaml.Marshal(actual)
	require.NoError(t, err)
	var restored EnvironmentSsh
	require.NoError(t, yaml.Unmarshal(roundtrip, &restored))
	require.True(t, actual.IsEqualTo(restored))
}

func TestEnvironmentSshRejectsInvalidCertificateConfiguration(t *testing.T) {
	for _, test := range []struct {
		name        string
		certificate string
		identity    string
	}{
		{name: "missing identity", certificate: "validity: 1h"},
		{name: "templated identity", certificate: "identityFile: '{{ .session.id }}'\nvalidity: 1h"},
		{name: "templated authority", certificate: "identityFile: target-key\nauthorityIdentityFile: '{{ .session.id }}'\nvalidity: 1h"},
		{name: "missing validity", certificate: "identityFile: target-key"},
		{name: "zero validity", certificate: "identityFile: target-key\nvalidity: 0s"},
		{name: "negative skew", certificate: "identityFile: target-key\nvalidity: 1h\nvalidAfterSkew: -1s"},
		{name: "empty principal", certificate: "identityFile: target-key\nvalidity: 1h\nprincipals: ['']"},
		{name: "identity modes", identity: "identityFiles: [other-key]\n", certificate: "identityFile: target-key\nvalidity: 1h"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var environment Environment
			plain := "type: ssh\naddress: target.example.org:22\nuser: alice\nacceptAllHostKeys: true\n" + test.identity + "certificate:\n"
			for _, line := range strings.Split(test.certificate, "\n") {
				plain += "  " + line + "\n"
			}
			require.Error(t, yaml.Unmarshal([]byte(plain), &environment))
		})
	}
}

func mustRenderDuration(t *testing.T, value interface {
	Render(any) (time.Duration, error)
}) time.Duration {
	t.Helper()
	result, err := value.Render(nil)
	require.NoError(t, err)
	return result
}

func mustRenderBool(t *testing.T, value interface {
	Render(any) (bool, error)
}) bool {
	t.Helper()
	result, err := value.Render(nil)
	require.NoError(t, err)
	return result
}
