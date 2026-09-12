//go:build windows

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestValidateSftpIdentityFilePermissionsOnWindows(t *testing.T) {
	name := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, os.WriteFile(name, []byte("key"), 0o600))
	require.NoError(t, secureJournalPath(name))
	info, err := os.Lstat(name)
	require.NoError(t, err)
	require.NoError(t, validateSftpIdentityFilePermissions(name, info))

	owner, err := currentProcessOwnerSid()
	require.NoError(t, err)
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;;FR;;;WD)(A;;FR;;;%s)", owner.String()))
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(name, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))
	err = validateSftpIdentityFilePermissions(name, info)
	require.ErrorContains(t, err, "identity other than its owner or SYSTEM")
}
