//go:build windows

package audit

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestEnsureIdentityAcceptsGeneratedWindowsKeyDACL(t *testing.T) {
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	_, err := auditIdentityKeyRequirement.CreateFile(nil, conf.IdentityFile)
	require.NoError(t, err)

	identity, err := EnsureIdentity(&conf)

	require.NoError(t, err)
	require.NotNil(t, identity)
}

func TestEnsureIdentityRejectsInsecureWindowsKeyDACL(t *testing.T) {
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	_, err := auditIdentityKeyRequirement.CreateFile(nil, conf.IdentityFile)
	require.NoError(t, err)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FR;;;WD)(A;;FA;;;OW)")
	require.NoError(t, err)
	dacl, _, err := descriptor.DACL()
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(conf.IdentityFile, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil))

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.ErrorContains(t, err, "identity other than")
}

func TestEnsureIdentityRejectsWindowsKeyHardLink(t *testing.T) {
	conf := auditIdentityTestConfiguration(t.TempDir(), true)
	_, err := auditIdentityKeyRequirement.CreateFile(nil, conf.IdentityFile)
	require.NoError(t, err)
	require.NoError(t, os.Link(conf.IdentityFile, conf.IdentityFile+".link"))

	identity, err := EnsureIdentity(&conf)

	require.Nil(t, identity)
	require.ErrorContains(t, err, "hard links")
}
