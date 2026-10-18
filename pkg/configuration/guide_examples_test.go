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

	for _, name := range []string{"ssh-gateway", "oidc", "recording", "management", "evidence"} {
		t.Run(name, func(t *testing.T) {
			markdown, err := os.ReadFile(filepath.Join("..", "..", "docs", "guides", name+".md"))
			require.NoError(t, err)
			yamlExample := firstGuideYAML(t, string(markdown))
			yamlExample = strings.ReplaceAll(yamlExample, "/etc/engity/bifroest/management_authorized_keys", keyFile)
			yamlExample = strings.ReplaceAll(yamlExample, "/etc/engity/bifroest/evidence-recipient.pub", keyFile)
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

func firstGuideYAML(t *testing.T, markdown string) string {
	t.Helper()
	lines := strings.Split(markdown, "\n")
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "```yaml" {
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		var content []string
		for _, next := range lines[index+1:] {
			if strings.TrimSpace(next) == "```" {
				return strings.Join(content, "\n")
			}
			content = append(content, strings.TrimPrefix(next, indent))
		}
		t.Fatal("guide has no closing YAML fence")
	}
	t.Fatal("guide has no YAML example")
	return ""
}
