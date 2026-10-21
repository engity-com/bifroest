package export

import (
	"bytes"
	crand "crypto/rand"
	goos "os"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestKeyExportPublicWritesOnlyPublicMaterial(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(crand.Reader, identityFile)
	require.NoError(t, err)

	var stdout bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &stdout, nil)
	require.NoError(t, handlePublic(ctx, publicOpts{IdentityFile: identityFile, Comment: "test", Output: "-"}))
	_, comment, _, rest, err := ssh.ParseAuthorizedKey(stdout.Bytes())
	require.NoError(t, err)
	require.Equal(t, "test", comment)
	require.Empty(t, bytes.TrimSpace(rest))
	require.NotContains(t, stdout.String(), "PRIVATE KEY")
}

func TestKeyExportPublicDoesNotReplacePrivateKeyWithForce(t *testing.T) {
	identityFile := filepath.Join(t.TempDir(), "identity")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(crand.Reader, identityFile)
	require.NoError(t, err)
	before, err := goos.ReadFile(identityFile)
	require.NoError(t, err)

	err = handlePublic(t.Context(), publicOpts{IdentityFile: identityFile, Output: identityFile, Force: true})
	require.ErrorContains(t, err, "must not replace private key")
	after, err := goos.ReadFile(identityFile)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
