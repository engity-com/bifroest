package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestSimpleTrustedUserCAsConfiguration(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	directory := t.TempDir()
	var conf Configuration
	require.NoError(t, conf.LoadFromYaml(strings.NewReader(fmt.Sprintf(`
ssh:
  addresses: ["127.0.0.1:0"]
  keys:
    hostKeys: ["%s"]
session:
  type: fs
  storage: "%s"
flows:
  - name: certificate
    authorization:
      type: simple
      trustedUserCAs: |
        %s
      entries:
        - name: alice
    environment:
      type: dummy
`, filepath.ToSlash(filepath.Join(directory, "host-key")), filepath.ToSlash(filepath.Join(directory, "sessions")), publicKey)), "certificate-test.yaml"))
	actual := conf.Flows[0].Authorization.V.(*AuthorizationSimple)
	require.Equal(t, publicKey, string(actual.TrustedUserCAs))
	require.Len(t, actual.Entries, 1)

	roundtrip, err := yaml.Marshal(actual)
	require.NoError(t, err)
	var restored AuthorizationSimple
	require.NoError(t, yaml.Unmarshal(roundtrip, &restored), string(roundtrip))
	require.True(t, actual.IsEqualTo(restored))
}

func TestTrustedUserCAsFileValidation(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0600))

	for name, file := range map[string]string{
		"missing": filepath.Join(directory, "missing"),
		"empty":   empty,
	} {
		t.Run(name, func(t *testing.T) {
			var authorization Authorization
			err := yaml.Unmarshal([]byte("type: simple\ntrustedUserCAsFile: '"+file+"'\nentries:\n  - name: alice\n"), &authorization)
			require.Error(t, err)
		})
	}
}
