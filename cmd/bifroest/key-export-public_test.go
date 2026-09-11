package main

import (
	"bytes"
	goos "os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestKeyExportPublicWritesOnlyPublicMaterial(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, doKeyGenerate(identityFile, ""))

	var stdout bytes.Buffer
	require.NoError(t, doKeyExportPublic(identityFile, "test", "-", false, &stdout))
	_, comment, _, rest, err := ssh.ParseAuthorizedKey(stdout.Bytes())
	require.NoError(t, err)
	require.Equal(t, "test", comment)
	require.Empty(t, bytes.TrimSpace(rest))
	require.NotContains(t, stdout.String(), "PRIVATE KEY")
}

func TestKeyExportPublicDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, doKeyGenerate(identityFile, ""))
	before, err := goos.ReadFile(identityFile)
	require.NoError(t, err)

	err = doKeyExportPublic(identityFile, "", identityFile, true, &bytes.Buffer{})
	require.ErrorContains(t, err, "must not replace private key")
	after, err := goos.ReadFile(identityFile)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
