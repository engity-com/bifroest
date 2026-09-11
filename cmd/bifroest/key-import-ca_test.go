package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyImportCaMergesCertificateAuthorities(t *testing.T) {
	directory := t.TempDir()
	identityFile := filepath.Join(directory, "ca")
	require.NoError(t, doKeyGenerate(identityFile, ""))
	var public bytes.Buffer
	require.NoError(t, doKeyExportPublic(identityFile, "", "-", false, &public))

	trustedCAsFile := filepath.Join(directory, "trusted-cas")
	require.NoError(t, doKeyImportCa(trustedCAsFile, "-", "", bytes.NewReader(public.Bytes())))
	require.NoError(t, doKeyImportCa(trustedCAsFile, "-", "", bytes.NewReader(public.Bytes())))
	require.FileExists(t, trustedCAsFile)
}
