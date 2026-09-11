package main

import (
	"bytes"
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestKeyGenerateKeepsPrivateMaterialOffPublicFile(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")
	publicFile := filepath.Join(directory, "identity.pub")

	require.NoError(t, doKeyGenerate(identityFile, publicFile))
	require.Error(t, doKeyGenerate(identityFile, publicFile))

	privateRaw, err := goos.ReadFile(identityFile)
	require.NoError(t, err)
	private, err := ssh.ParsePrivateKey(privateRaw)
	require.NoError(t, err)
	publicRaw, err := goos.ReadFile(publicFile)
	require.NoError(t, err)
	public, _, _, rest, err := ssh.ParseAuthorizedKey(publicRaw)
	require.NoError(t, err)
	require.Empty(t, bytes.TrimSpace(rest))
	require.Equal(t, private.PublicKey().Marshal(), public.Marshal())
	require.NotContains(t, string(publicRaw), "PRIVATE KEY")
}

func TestKeyGenerateWithoutPublicFile(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, doKeyGenerate(identityFile, ""))
	require.FileExists(t, identityFile)
}

func TestKeyGenerateRejectsPublicFileBeforeCreatingPrivateKey(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "identity")
	publicFile := filepath.Join(directory, "identity.pub")
	require.NoError(t, goos.WriteFile(publicFile, []byte("existing"), 0600))

	require.Error(t, doKeyGenerate(identityFile, publicFile))
	require.NoFileExists(t, identityFile)
	actual, err := goos.ReadFile(publicFile)
	require.NoError(t, err)
	require.Equal(t, []byte("existing"), actual)
}

func TestKeyGenerateRejectsSamePrivateAndPublicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	require.Error(t, doKeyGenerate(path, path))
	require.NoFileExists(t, path)
}
