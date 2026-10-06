//go:build !windows

package managementclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestManagementClientCanSignUsingUnixSSHAgent(t *testing.T) {
	directory, err := os.MkdirTemp("", "bfa-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	socket := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer listener.Close()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: private}))
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		served <- agent.ServeAgent(keyring, conn)
	}()
	client, closer, err := connectAgent(socket)
	require.NoError(t, err)
	require.NotNil(t, closer)
	signers, err := client.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)
	message := []byte("management-agent-test")
	signature, err := signers[0].Sign(rand.Reader, message)
	require.NoError(t, err)
	require.NoError(t, signers[0].PublicKey().Verify(message, signature))
	require.NoError(t, closer.Close())
	serveErr := <-served // ServeAgent ends when the client socket closes.
	require.True(t, serveErr == nil || errors.Is(serveErr, io.EOF), "unexpected agent error: %v", serveErr)
	other, closeOther, err := connectAgent("none")
	require.NoError(t, err)
	require.Nil(t, other)
	require.Nil(t, closeOther)
}
