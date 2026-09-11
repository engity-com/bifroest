//go:build windows

package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGeneratedPrivateKeyHasProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	requireProtectedDACL(t, path)
}

func TestBootstrapFileHasProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-hosts")
	require.NoError(t, WriteBootstrapFile(path, []byte("first\n"), false))
	requireProtectedDACL(t, path)

	require.NoError(t, WriteBootstrapFile(path, []byte("replacement\n"), true))
	requireProtectedDACL(t, path)
}

func TestProtectedTempFileHasProtectedDACLWhileOpen(t *testing.T) {
	file, err := createProtectedTempFile(t.TempDir(), ".protected-*", 0600)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, file.Close())
		require.NoError(t, os.Remove(file.Name()))
	})
	requireProtectedDACL(t, file.Name())
}

func TestBootstrapFileSupportsLongWindowsPath(t *testing.T) {
	directory := t.TempDir()
	for len(directory) < 280 {
		directory = filepath.Join(directory, strings.Repeat("a", 40))
	}
	require.NoError(t, os.MkdirAll(directory, 0700))
	path := filepath.Join(directory, "known-hosts")
	require.NoError(t, WriteBootstrapFile(path, []byte("content\n"), false))
	requireProtectedDACL(t, path)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("content\n"), raw)
}

func TestReadPrivateKeyFileRetriesTransientWindowsErrors(t *testing.T) {
	for _, transient := range []error{windows.ERROR_SHARING_VIOLATION, windows.ERROR_LOCK_VIOLATION} {
		attempts := 0
		raw, err := readPrivateKeyFileUsing("identity", func(path string) ([]byte, error) {
			require.Equal(t, "identity", path)
			attempts++
			if attempts == 1 {
				return nil, transient
			}
			return []byte("private key"), nil
		}, func(_ time.Duration) {})
		require.NoError(t, err)
		require.Equal(t, []byte("private key"), raw)
		require.Equal(t, 2, attempts)
	}
}

func TestReadPrivateKeyFileBoundsRetriesAndReturnsOtherErrorsImmediately(t *testing.T) {
	attempts := 0
	_, err := readPrivateKeyFileUsing("identity", func(string) ([]byte, error) {
		attempts++
		return nil, windows.ERROR_SHARING_VIOLATION
	}, func(_ time.Duration) {})
	require.ErrorIs(t, err, windows.ERROR_SHARING_VIOLATION)
	require.Equal(t, 100, attempts)

	attempts = 0
	_, err = readPrivateKeyFileUsing("identity", func(string) ([]byte, error) {
		attempts++
		return nil, windows.ERROR_ACCESS_DENIED
	}, func(_ time.Duration) {})
	require.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
	require.Equal(t, 1, attempts)
}

func requireProtectedDACL(t *testing.T, path string) {
	t.Helper()
	extended, err := windowsExtendedPath(path)
	require.NoError(t, err)
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := descriptor.Control()
	require.NoError(t, err)
	require.NotZero(t, control&windows.SE_DACL_PROTECTED)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NotNil(t, dacl)
	require.Equal(t, uint16(2), dacl.AceCount)
	actualSIDs := make([]string, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, i, &ace))
		require.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType)
		require.Equal(t, windows.ACCESS_MASK(0x001f01ff), ace.Mask)
		actualSIDs = append(actualSIDs, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	require.ElementsMatch(t, []string{"S-1-5-18", "S-1-3-4"}, actualSIDs)
}
