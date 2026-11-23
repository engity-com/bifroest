//go:build windows

package conpty

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestLibraryLoadsOnlyTheProtectedEmbeddedDLLAndCleansUp(t *testing.T) {
	library, err := Load()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, library.Close()) })
	directory := library.directory
	path := filepath.Join(directory, "conpty.dll")
	raw, err := bfcrypto.ReadSecurePrivateFile(path, 2<<20)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.NotNil(t, library.release, "the release export is required, not an optional legacy fallback")
	require.Error(t, os.WriteFile(path, []byte("replaced"), 0600))
	require.Error(t, os.Rename(path, path+".moved"))
	require.Error(t, os.Remove(path))
	require.Error(t, os.Rename(directory, directory+".moved"))
	_, err = os.Stat(filepath.Join(directory, "OpenConsole.exe"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, library.Close())
	_, err = os.Stat(directory)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLibraryRejectsTamperedAndUnprotectedPayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conpty.dll")
	require.NoError(t, os.WriteFile(path, []byte("not a DLL"), 0600))
	_, err := lockPayload(path, Payloads[0])
	require.Error(t, err, "Windows mode 0600 alone is not a protected DACL")
	require.NoError(t, bfcrypto.WriteBootstrapFile(path, []byte("not a DLL"), true))
	_, err = lockPayload(path, Payloads[0])
	require.ErrorContains(t, err, "digest mismatch")
}

func TestLibraryPreservesHRESULTFailuresAndPacksCoordByValue(t *testing.T) {
	require.Equal(t, uintptr(80|25<<16), packedSize(windows.Coord{X: 80, Y: 25}))
	require.NoError(t, hresult("release", 0))
	require.NoError(t, hresult("release", 1))
	require.ErrorContains(t, hresult("release", 0x80070005), "HRESULT 0x80070005")
}
