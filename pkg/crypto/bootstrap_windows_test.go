//go:build windows

package crypto

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGeneratedPrivateKeyHasProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := descriptor.Control()
	require.NoError(t, err)
	require.NotZero(t, control&windows.SE_DACL_PROTECTED)
}
