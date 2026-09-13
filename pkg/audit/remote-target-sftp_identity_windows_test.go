//go:build windows

package audit

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func TestLoadSftpIdentityFileValidatesWindowsPermissions(t *testing.T) {
	name := filepath.Join(t.TempDir(), "identity")
	_, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(nil, name)
	require.NoError(t, err)
	_, err = loadSftpIdentityFile(name)
	require.NoError(t, err)

	owner, err := currentProcessOwnerSid()
	require.NoError(t, err)
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FR;;;WD)(A;;FR;;;%s)", owner.String()))
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))
	_, err = loadSftpIdentityFile(name)
	require.ErrorContains(t, err, "identity other than its owner, OWNER RIGHTS, or SYSTEM")
}
