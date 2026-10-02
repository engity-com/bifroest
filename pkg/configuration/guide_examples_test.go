package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestGuideConfigurations(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshKey, err := ssh.NewPublicKey(publicKey)
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "gateway-clients.pub")
	require.NoError(t, os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(sshKey), 0600))
	hostsFile := filepath.Join(t.TempDir(), "target_known_hosts")
	require.NoError(t, os.WriteFile(hostsFile, []byte(knownhosts.Line([]string{"target.example.org"}, sshKey)+"\n"), 0600))

	for _, name := range []string{"ssh-gateway", "oidc", "recording"} {
		t.Run(name, func(t *testing.T) {
			markdown, err := os.ReadFile(filepath.Join("..", "..", "docs", "guides", name+".md"))
			require.NoError(t, err)
			_, after, found := strings.Cut(string(markdown), "```yaml\n")
			require.True(t, found, "guide has no YAML example")
			yamlExample, _, found := strings.Cut(after, "\n```")
			require.True(t, found, "guide has no closing YAML fence")
			if name == "ssh-gateway" {
				require.Contains(t, yamlExample, "/etc/engity/bifroest/gateway-clients.pub")
				yamlExample = strings.ReplaceAll(yamlExample, "/etc/engity/bifroest/gateway-clients.pub", keyFile)
				yamlExample = strings.ReplaceAll(yamlExample, "/etc/engity/bifroest/target_known_hosts", hostsFile)
			}
			if name == "oidc" {
				require.Contains(t, yamlExample, "offline_access")
			}
			var conf Configuration
			require.NoError(t, conf.LoadFromYaml(strings.NewReader(yamlExample), name+".md"))
		})
	}
}
