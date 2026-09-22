//go:build windows

package recording

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestBindLocalFormatRejectsHardLinkedCleanupTombstone(t *testing.T) {
	root := t.TempDir()
	tombstone := filepath.Join(root, localFormatTempFileName+localRetentionTombstone)
	external := filepath.Join(t.TempDir(), "external")
	payload := []byte("must survive")
	require.NoError(t, os.WriteFile(external, payload, localFileMode))
	require.NoError(t, os.Link(external, tombstone))
	require.NoError(t, os.Chmod(external, 0400))
	t.Cleanup(func() { _ = os.Chmod(external, localFileMode) })
	before, err := os.Lstat(external)
	require.NoError(t, err)
	beforeDACL := localWindowsDACL(t, external)

	err = bindLocalFormat(root, "cast-zstd/v1")
	require.ErrorContains(t, err, "multiple hard links")
	actual, readErr := os.ReadFile(external)
	require.NoError(t, readErr)
	require.Equal(t, payload, actual)
	after, statErr := os.Lstat(external)
	require.NoError(t, statErr)
	require.Equal(t, before.Mode().Perm(), after.Mode().Perm())
	require.Equal(t, beforeDACL, localWindowsDACL(t, external))
}

func TestLocalMetadataHandleSupportsValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata")
	require.NoError(t, os.WriteFile(path, []byte("metadata"), localFileMode))
	expected, err := os.Lstat(path)
	require.NoError(t, err)
	file, err := openLocalMetadataPath(path, false, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	require.NoError(t, validateLocalMetadataHandle(path, file, expected, true))
}

func TestSealLocalFileRejectsHardLinkBeforeChangingMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "recording.cast.zst")
	external := filepath.Join(t.TempDir(), "external")
	require.NoError(t, os.WriteFile(external, []byte("recording"), localFileMode))
	require.NoError(t, os.Link(external, path))
	file, err := os.OpenFile(path, os.O_RDWR, localFileMode)
	require.NoError(t, err)
	before, err := os.Lstat(external)
	require.NoError(t, err)
	beforeDACL := localWindowsDACL(t, external)

	err = sealLocalFile(path, file)
	require.ErrorContains(t, err, "multiple hard links")
	require.NoError(t, file.Close())
	after, err := os.Lstat(external)
	require.NoError(t, err)
	require.Equal(t, before.Mode().Perm(), after.Mode().Perm())
	require.Equal(t, beforeDACL, localWindowsDACL(t, external))
}

func TestRemoveLocalFileCleansProtectedWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery.reserve")
	file, err := createLocalFile(path)
	require.NoError(t, err)
	require.NoError(t, protectLocalReadOnlyFile(path, file))
	require.NoError(t, file.Close())
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.NotZero(t, info.Mode().Perm()&0200)

	require.NoError(t, removeLocalFile(path))
	require.NoFileExists(t, path)
	require.NoFileExists(t, path+localRetentionTombstone)
}

func localWindowsDACL(t *testing.T, path string) []byte {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := descriptor.Control()
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NotNil(t, dacl)
	result := make([]byte, 4)
	binary.LittleEndian.PutUint16(result, uint16(control))
	binary.LittleEndian.PutUint16(result[2:], dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, index, &ace))
		result = append(result, unsafe.Slice((*byte)(unsafe.Pointer(ace)), int(ace.Header.AceSize))...)
	}
	return result
}
