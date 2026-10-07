package _import

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/cli/key"
	"github.com/engity-com/bifroest/pkg/cli/key/export"
)

func TestKeyImportCaMergesCertificateAuthorities(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "ca")
	require.NoError(t, key.doKeyGenerate(identityFile, ""))
	var public bytes.Buffer
	require.NoError(t, export.doKeyExportPublic(identityFile, "", "-", false, &public))

	trustedCAsFile := filepath.Join(directory, "trusted-cas")
	require.NoError(t, handleCa(trustedCAsFile, "-", "", bytes.NewReader(public.Bytes())))
	require.NoError(t, handleCa(trustedCAsFile, "-", "", bytes.NewReader(public.Bytes())))
	require.FileExists(t, trustedCAsFile)
}
