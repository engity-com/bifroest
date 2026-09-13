//go:build windows

package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLoadSecurePrivateKeyFileAcceptsOwnerRightsAndRejectsForeignSid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	_, err = LoadSecurePrivateKeyFile(path, 1<<20)
	require.NoError(t, err)

	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))
	_, err = LoadSecurePrivateKeyFile(path, 1<<20)
	require.ErrorContains(t, err, "identity other than")
}

func TestLoadSecurePrivateKeyFileRejectsWindowsHardLink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	_, err := (KeyRequirement{Type: KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	require.NoError(t, os.Link(path, path+".link"))

	_, err = LoadSecurePrivateKeyFile(path, 1<<20)
	require.ErrorContains(t, err, "hard links")
}
