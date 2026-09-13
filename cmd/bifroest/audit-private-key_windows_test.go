//go:build windows

package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestLoadAuditPrivateKeyRejectsPermissiveDACLOnWindows(t *testing.T) {
	directory := t.TempDir()
	privateKey := filepath.Join(directory, "identity")
	publicKey := filepath.Join(directory, "identity.pub")
	require.NoError(t, doKeyGenerate(privateKey, publicKey))
	_, err := loadAuditPrivateKey(privateKey)
	require.NoError(t, err)

	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(privateKey, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))

	_, err = loadAuditPrivateKey(privateKey)
	require.ErrorContains(t, err, "identity other than")
	require.FileExists(t, privateKey)
}
