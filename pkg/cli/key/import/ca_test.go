package _import

import (
	"bytes"
	crand "crypto/rand"
	"path/filepath"
	"testing"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestKeyImportCaMergesCertificateAuthorities(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "ca")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(crand.Reader, identityFile)
	require.NoError(t, err)
	public, err := bfcrypto.ExportPublicKey(identityFile, "")
	require.NoError(t, err)

	trustedCAsFile := filepath.Join(directory, "trusted-cas")
	for range 2 {
		ctx := cli.ContextWithStdio(t.Context(), bytes.NewReader(public), nil, nil)
		require.NoError(t, handleCa(ctx, caOpts{TrustedCAsFile: trustedCAsFile, Input: "-"}))
	}
	require.FileExists(t, trustedCAsFile)
}
