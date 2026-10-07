package _import

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	goos "os"
	"path/filepath"
	"testing"

	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/key"
	"github.com/engity-com/bifroest/pkg/cli/key/export"
)

func TestKeyImportHostUsesExplicitInputAndIsIdempotent(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")
	require.NoError(t, key.doKeyGenerate(identityFile, ""))
	hostKeyFile := filepath.Join(directory, "host-key")
	require.NoError(t, export.doKeyExportHost(&export.keyExportHostOpts{identityFile: identityFile, address: "host.example", output: hostKeyFile}, &bytes.Buffer{}))

	knownHostsFile := filepath.Join(directory, "known-hosts")
	require.NoError(t, handleHost(&hostOpts{KnownHostsFile: knownHostsFile, Input: hostKeyFile}, bytes.NewReader([]byte("unused"))))
	first, err := goos.ReadFile(knownHostsFile)
	require.NoError(t, err)
	require.NoError(t, handleHost(&hostOpts{KnownHostsFile: knownHostsFile, ExpectedFingerprint: "unknown"}, bytes.NewReader(first)))
	second, err := goos.ReadFile(knownHostsFile)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestKeyImportHostRetrievesKeyFromAddress(t *testing.T) {
	address, key, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := hostOpts{
		KnownHostsFile:      knownHostsFile,
		Address:             address,
		ExpectedFingerprint: ssh.FingerprintSHA256(key),
	}
	require.NoError(t, handleHost(&opts, &bytes.Buffer{}))
	require.Error(t, <-serverDone)
	require.FileExists(t, knownHostsFile)
}

func TestKeyImportHostAllowsExplicitUnknownFingerprint(t *testing.T) {
	testlog.Hook(t)
	address, _, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := hostOpts{
		KnownHostsFile:      knownHostsFile,
		Address:             address,
		ExpectedFingerprint: "unknown",
	}
	require.NoError(t, handleHost(&opts, &bytes.Buffer{}))
	require.Error(t, <-serverDone)
	require.FileExists(t, knownHostsFile)
}

func TestKeyImportHostRequiresNetworkFingerprintAndRejectsInput(t *testing.T) {
	for _, opts := range []hostOpts{
		{KnownHostsFile: "known-hosts", Address: "host.example"},
		{KnownHostsFile: "known-hosts", Address: "host.example", Input: "input", ExpectedFingerprint: "unknown"},
	} {
		require.Error(t, handleHost(&opts, &bytes.Buffer{}))
	}
}

func TestKeyImportHostFingerprintMismatchDoesNotCreateFile(t *testing.T) {
	address, _, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := hostOpts{
		KnownHostsFile:      knownHostsFile,
		Address:             address,
		ExpectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	require.Error(t, handleHost(&opts, &bytes.Buffer{}))
	require.Error(t, <-serverDone)
	require.NoFileExists(t, knownHostsFile)
}

func startKeyImportHostTestServer(t *testing.T) (string, ssh.PublicKey, <-chan error) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		server, _, _, serverErr := ssh.NewServerConn(connection, config)
		if server != nil {
			_ = server.Close()
		}
		serverDone <- serverErr
	}()
	return listener.Addr().String(), signer.PublicKey(), serverDone
}
