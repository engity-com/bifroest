//go:build windows

package audit

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestLoadAuditPrivateKeyRejectsPermissiveDACLOnWindows(t *testing.T) {
	directory := t.TempDir()
	privateKey := filepath.Join(directory, "identity")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(rand.Reader, privateKey)
	require.NoError(t, err)
	_, err = LoadAuditPrivateKey(privateKey)
	require.NoError(t, err)

	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)(A;;FR;;;WD)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(privateKey, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))

	_, err = LoadAuditPrivateKey(privateKey)
	require.ErrorContains(t, err, "identity other than")
	require.FileExists(t, privateKey)
}
