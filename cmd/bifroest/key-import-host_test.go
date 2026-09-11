package main

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
)

func TestKeyImportHostUsesExplicitInputAndIsIdempotent(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")
	require.NoError(t, doKeyGenerate(identityFile, ""))
	hostKeyFile := filepath.Join(directory, "host-key")
	require.NoError(t, doKeyExportHost(&keyExportHostOpts{identityFile: identityFile, address: "host.example", output: hostKeyFile}, &bytes.Buffer{}))

	knownHostsFile := filepath.Join(directory, "known-hosts")
	require.NoError(t, doKeyImportHost(&keyImportHostOpts{knownHostsFile: knownHostsFile, input: hostKeyFile}, bytes.NewReader([]byte("unused"))))
	first, err := goos.ReadFile(knownHostsFile)
	require.NoError(t, err)
	require.NoError(t, doKeyImportHost(&keyImportHostOpts{knownHostsFile: knownHostsFile, expectedFingerprint: "unknown"}, bytes.NewReader(first)))
	second, err := goos.ReadFile(knownHostsFile)
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestKeyImportHostRetrievesKeyFromAddress(t *testing.T) {
	address, key, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := keyImportHostOpts{
		knownHostsFile:      knownHostsFile,
		address:             address,
		expectedFingerprint: ssh.FingerprintSHA256(key),
	}
	require.NoError(t, doKeyImportHost(&opts, &bytes.Buffer{}))
	require.Error(t, <-serverDone)
	require.FileExists(t, knownHostsFile)
}

func TestKeyImportHostAllowsExplicitUnknownFingerprint(t *testing.T) {
	testlog.Hook(t)
	address, _, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := keyImportHostOpts{
		knownHostsFile:      knownHostsFile,
		address:             address,
		expectedFingerprint: "unknown",
	}
	require.NoError(t, doKeyImportHost(&opts, &bytes.Buffer{}))
	require.Error(t, <-serverDone)
	require.FileExists(t, knownHostsFile)
}

func TestKeyImportHostRequiresNetworkFingerprintAndRejectsInput(t *testing.T) {
	for _, opts := range []keyImportHostOpts{
		{knownHostsFile: "known-hosts", address: "host.example"},
		{knownHostsFile: "known-hosts", address: "host.example", input: "input", expectedFingerprint: "unknown"},
	} {
		require.Error(t, doKeyImportHost(&opts, &bytes.Buffer{}))
	}
}

func TestKeyImportHostFingerprintMismatchDoesNotCreateFile(t *testing.T) {
	address, _, serverDone := startKeyImportHostTestServer(t)
	knownHostsFile := filepath.Join(t.TempDir(), "known-hosts")
	opts := keyImportHostOpts{
		knownHostsFile:      knownHostsFile,
		address:             address,
		expectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	require.Error(t, doKeyImportHost(&opts, &bytes.Buffer{}))
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
