package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newKnownHostsTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	result, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	return result
}

func knownHostsTestLine(marker, host string, key ssh.PublicKey) string {
	prefix := ""
	if marker != "" {
		prefix = "@" + marker + " "
	}
	return fmt.Sprintf("%s%s %s", prefix, host, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
}

func TestNewKnownHostsCallbackAcceptsInlineAndFileEntries(t *testing.T) {
	inlineKey := newKnownHostsTestKey(t)
	fileKey := newKnownHostsTestKey(t)
	file := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(file, []byte(knownHostsTestLine("", "file.example.org", fileKey)), 0600))

	callback, err := NewKnownHostsCallback(
		KnownHosts(knownHostsTestLine("", "inline.example.org", inlineKey)),
		KnownHostsFile(file),
	)
	require.NoError(t, err)

	address := &gonet.TCPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 22}
	require.NoError(t, callback("inline.example.org:22", address, inlineKey))
	require.NoError(t, callback("file.example.org:22", address, fileKey))
}

func TestNewKnownHostsCallbackHonorsRevocationAcrossSources(t *testing.T) {
	key := newKnownHostsTestKey(t)
	file := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(file, []byte(knownHostsTestLine("revoked", "target.example.org", key)), 0600))

	callback, err := NewKnownHostsCallback(
		KnownHosts(knownHostsTestLine("", "target.example.org", key)),
		KnownHostsFile(file),
	)
	require.NoError(t, err)

	err = callback("target.example.org:22", &gonet.TCPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 22}, key)
	var revoked *knownhosts.RevokedError
	require.ErrorAs(t, err, &revoked)
}

func TestKnownHostsRejectsCommentOnlyAndMalformedInput(t *testing.T) {
	require.Error(t, KnownHosts("# only a comment").Validate())
	require.Error(t, KnownHosts("target.example.org not-a-key").Validate())
	require.Error(t, KnownHosts(knownHostsTestLine("unknown", "target.example.org", newKnownHostsTestKey(t))).Validate())
	require.Error(t, KnownHosts(knownHostsTestLine("", "!", newKnownHostsTestKey(t))).Validate())
}
