//go:build windows

package sys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestOpenFileForRotationSharesDeleteAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "material")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	reader, err := OpenFileForRotation(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })

	name, err := WindowsPathPointer(path)
	require.NoError(t, err)
	// A normal os.Open handle blocks DELETE access; the rotation reader must not.
	handle, err := windows.CreateFile(name, windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, windows.CloseHandle(handle)) })
}
