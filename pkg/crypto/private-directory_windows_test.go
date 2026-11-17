//go:build windows

package crypto

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestPrivateDirectoryRejectsForeignAccessWithoutRepairingTheAcl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	directory, err := EnsurePrivateDirectory(path)
	require.NoError(t, err)
	require.NoError(t, directory.Close())
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))
	_, err = EnsurePrivateDirectory(path)
	require.ErrorContains(t, err, "identity other than")
	_, err = EnsurePrivateDirectory(path)
	require.ErrorContains(t, err, "identity other than", "rejected permissions must not be repaired")
}
