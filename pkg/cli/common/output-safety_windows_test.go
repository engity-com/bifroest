package common

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func denyOutputDirectoryListing(t *testing.T, directory string) {
	t.Helper()
	original, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	originalDACL, _, err := original.DACL()
	require.NoError(t, err)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(D;;0x1;;;OW)(A;;FA;;;OW)(A;;FA;;;SY)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil))
	t.Cleanup(func() {
		require.NoError(t, windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, originalDACL, nil))
	})
	_, err = os.ReadDir(directory)
	require.ErrorIs(t, err, fs.ErrPermission)
}
