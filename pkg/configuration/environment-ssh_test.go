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
