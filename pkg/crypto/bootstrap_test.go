package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

func TestBootstrapKeyExportAndNoClobber(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, identityFile)
	require.NoError(t, err)

	public, err := ExportPublicKey(identityFile, "bootstrap-test")
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(public, []byte(" bootstrap-test\n")))
	key, comment, options, rest, err := ssh.ParseAuthorizedKey(public)
	require.NoError(t, err)
	require.NotNil(t, key)
	require.Equal(t, "bootstrap-test", comment)
	require.Empty(t, options)
	require.Empty(t, bytes.TrimSpace(rest))

	output := filepath.Join(directory, "public")
	require.NoError(t, WriteBootstrapFile(output, public, false))
	require.Error(t, WriteBootstrapFile(output, []byte("replacement"), false))
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, public, actual)
	require.NoError(t, WriteBootstrapFile(output, []byte("replacement\n"), true))
}

func TestExportKnownHostKeyAddresses(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	private, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, identityFile)
	require.NoError(t, err)

	for _, address := range []string{"host.example", "host.example:22", "host.example:2222", "2001:db8::1", "[2001:db8::1]", "[2001:db8::1]:22", "[2001:db8::1]:2222"} {
		t.Run(address, func(t *testing.T) {
			actual, err := ExportKnownHostKey(identityFile, address)
			require.NoError(t, err)
			resolved, err := bfssh.ParseAddress(address)
			require.NoError(t, err)
			marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(actual)
			require.NoError(t, err)
			require.Empty(t, marker)
			require.Equal(t, []string{knownhosts.Normalize(resolved.String())}, hosts)
			require.Equal(t, private.PublicKey().Marshal(), key.Marshal())
			require.Empty(t, bytes.TrimSpace(rest))
		})
	}
	implicit, err := ExportKnownHostKey(identityFile, "host.example")
	require.NoError(t, err)
	explicit, err := ExportKnownHostKey(identityFile, "host.example:22")
	require.NoError(t, err)
	require.Equal(t, implicit, explicit)
}

func TestImportCertificateAuthoritiesIsValidatedAndIdempotent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "trusted-user-cas")
	input := append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(ed255191Pub)), []byte(" first\n")...)
	added, err := ImportCertificateAuthoritiesFile(target, input, ssh.FingerprintSHA256(ed255191Pub))
	require.NoError(t, err)
	require.Equal(t, 1, added)
	original, err := os.ReadFile(target)
	require.NoError(t, err)

	added, err = ImportCertificateAuthoritiesFile(target, input, ssh.FingerprintSHA256(ed255191Pub))
	require.NoError(t, err)
	require.Zero(t, added)
	afterIdempotentImport, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, original, afterIdempotentImport)

	second := ssh.MarshalAuthorizedKey(ed255192Pub)
	_, err = ImportCertificateAuthoritiesFile(target, second, ssh.FingerprintSHA256(ed255191Pub))
	require.Error(t, err)
	afterMismatch, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	require.Equal(t, original, afterMismatch)

	_, err = ImportCertificateAuthoritiesFile(target, append([]byte("restrict "), second...), "")
	require.Error(t, err)
}

func TestImportKnownHostsRejectsSpecialEntries(t *testing.T) {
	target := filepath.Join(t.TempDir(), "known-hosts")
	line := []byte(knownhosts.Line([]string{"host.example"}, ed255191Pub) + "\n")
	added, err := ImportKnownHostsFile(target, line, ssh.FingerprintSHA256(ed255191Pub))
	require.NoError(t, err)
	require.Equal(t, 1, added)

	added, err = ImportKnownHostsFile(target, line, ssh.FingerprintSHA256(ed255191Pub))
	require.NoError(t, err)
	require.Zero(t, added)

	_, err = ImportKnownHostsFile(target, line, ssh.FingerprintSHA256(ed255192Pub))
	require.Error(t, err)

	_, err = ImportKnownHostsFile(target, append([]byte("@revoked "), line...), "")
	require.Error(t, err)

	secondAddress := []byte(knownhosts.Line([]string{"another.example"}, ed255191Pub) + "\n")
	added, err = ImportKnownHostsFile(target, secondAddress, ssh.FingerprintSHA256(ed255191Pub))
	require.NoError(t, err)
	require.Equal(t, 1, added)
	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Contains(t, string(actual), "host.example")
	require.Contains(t, string(actual), "another.example")
}

func TestConcurrentTrustImportsDoNotLoseUpdates(t *testing.T) {
	target := filepath.Join(t.TempDir(), "trusted-user-cas")
	inputs := [][]byte{ssh.MarshalAuthorizedKey(ed255191Pub), ssh.MarshalAuthorizedKey(ed255192Pub)}
	errors := make(chan error, len(inputs))
	var wait sync.WaitGroup
	for _, input := range inputs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := ImportCertificateAuthoritiesFile(target, input, "")
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}

	actual, err := os.ReadFile(target)
	require.NoError(t, err)
	entries, err := parseExistingCertificateAuthorities(actual)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}
