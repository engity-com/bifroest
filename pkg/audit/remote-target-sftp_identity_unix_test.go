//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type sftpIdentityFileInfoWithOwner struct {
	os.FileInfo
	owner syscall.Stat_t
}

func (this sftpIdentityFileInfoWithOwner) Sys() any {
	return &this.owner
}

func TestLoadSftpIdentityFileRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid-key")
	require.NoError(t, os.WriteFile(valid, []byte("invalid key syntax"), 0o600))

	tests := []struct {
		name        string
		prepare     func(string)
		errorSuffix string
	}{
		{
			name: "group-readable",
			prepare: func(name string) {
				require.NoError(t, os.WriteFile(name, []byte("key"), 0o640))
			},
			errorSuffix: "accessible by group or others",
		},
		{
			name: "symlink",
			prepare: func(name string) {
				require.NoError(t, os.Symlink(valid, name))
			},
			errorSuffix: "not a regular file",
		},
		{
			name: "too-large",
			prepare: func(name string) {
				file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
				require.NoError(t, err)
				require.NoError(t, file.Truncate(maximumSftpIdentityFileSize+1))
				require.NoError(t, file.Close())
			},
			errorSuffix: "exceeds",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name := filepath.Join(directory, test.name)
			test.prepare(name)
			_, err := loadSftpIdentityFile(name)
			require.ErrorContains(t, err, test.errorSuffix)
		})
	}
}

func TestValidateSftpIdentityFilePermissionsRejectsDifferentOwner(t *testing.T) {
	name := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, os.WriteFile(name, []byte("key"), 0o600))
	info, err := os.Lstat(name)
	require.NoError(t, err)
	owner := *info.Sys().(*syscall.Stat_t)
	owner.Uid = uint32(os.Geteuid() + 1)

	err = validateSftpIdentityFilePermissions(name, sftpIdentityFileInfoWithOwner{FileInfo: info, owner: owner})
	require.ErrorContains(t, err, "is owned by user")
}
