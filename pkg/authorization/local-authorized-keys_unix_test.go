//go:build unix

package authorization

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestSecureLocalAuthorizedKeysReaderReadsRegularFile(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte("expected"), 0600))

	actual, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
	require.NoError(t, err)
	require.Equal(t, []byte("expected"), actual)
}

func TestSecureLocalAuthorizedKeysReaderRejectsRelativePath(t *testing.T) {
	_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))("authorized_keys")
	require.ErrorContains(t, err, "not absolute")
}

func TestSecureLocalAuthorizedKeysReaderAllowsMissingOptionalFile(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "missing")
	called := false

	_, err := crypto.DoWithEachAuthorizedKeyUsingReader[bool](false, secureLocalAuthorizedKeysReader(user.Id(os.Geteuid())), func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, bool, error) {
		called = true
		return false, false, nil
	}, path)
	require.NoError(t, err)
	require.False(t, called)
}

func TestSecureLocalAuthorizedKeysReaderRejectsSymlinks(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	realDirectory := filepath.Join(directory, "real")
	require.NoError(t, os.Mkdir(realDirectory, 0700))
	realFile := filepath.Join(realDirectory, "authorized_keys")
	require.NoError(t, os.WriteFile(realFile, []byte("key"), 0600))

	t.Run("final", func(t *testing.T) {
		path := filepath.Join(directory, "authorized_keys")
		require.NoError(t, os.Symlink(realFile, path))

		_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
		require.Error(t, err)
	})

	t.Run("parent", func(t *testing.T) {
		parent := filepath.Join(directory, "alias")
		require.NoError(t, os.Symlink(realDirectory, parent))

		_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(filepath.Join(parent, "authorized_keys"))
		require.Error(t, err)
	})
}

func TestSecureLocalAuthorizedKeysReaderRejectsWritablePaths(t *testing.T) {
	tests := map[string]struct {
		parentMode os.FileMode
		fileMode   os.FileMode
	}{
		"group-writable parent": {parentMode: 0770, fileMode: 0600},
		"world-writable parent": {parentMode: 0702, fileMode: 0600},
		"group-writable file":   {parentMode: 0700, fileMode: 0620},
		"world-writable file":   {parentMode: 0700, fileMode: 0602},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			directory := newSecureLocalAuthorizedKeysTestDirectory(t)
			parent := filepath.Join(directory, "user")
			require.NoError(t, os.Mkdir(parent, 0700))
			path := filepath.Join(parent, "authorized_keys")
			require.NoError(t, os.WriteFile(path, []byte("key"), 0600))
			require.NoError(t, os.Chmod(parent, test.parentMode))
			require.NoError(t, os.Chmod(path, test.fileMode))

			_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
			require.ErrorContains(t, err, "writable by group or others")
		})
	}
}

func TestSecureLocalAuthorizedKeysReaderRejectsWrongOwner(t *testing.T) {
	uid := uint32(1001)
	wrongUid := uint32(1002)

	tests := map[string]struct {
		directory bool
	}{
		"parent": {directory: true},
		"file":   {directory: false},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stat := unix.Stat_t{Uid: wrongUid, Nlink: 1}
			if test.directory {
				stat.Mode = unix.S_IFDIR | 0700
			} else {
				stat.Mode = unix.S_IFREG | 0600
			}

			err := validateLocalAuthorizedKeysStat("/secure/path", uid, test.directory, &stat)
			require.ErrorContains(t, err, "instead of root or target user")
		})
	}
}

func TestSecureLocalAuthorizedKeysReaderRejectsNonRegularFiles(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"directory": func(t *testing.T, path string) {
			require.NoError(t, os.Mkdir(path, 0700))
		},
		"fifo": func(t *testing.T, path string) {
			require.NoError(t, unix.Mkfifo(path, 0600))
		},
	}

	for name, create := range tests {
		t.Run(name, func(t *testing.T) {
			directory := newSecureLocalAuthorizedKeysTestDirectory(t)
			path := filepath.Join(directory, "authorized_keys")
			create(t, path)

			_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
			require.ErrorContains(t, err, "not a regular file")
		})
	}
}

func TestSecureLocalAuthorizedKeysReaderRejectsHardLink(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte("key"), 0600))
	require.NoError(t, os.Link(path, filepath.Join(directory, "second-link")))

	_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
	require.ErrorContains(t, err, "hard links instead of one")
}

func TestSecureLocalAuthorizedKeysReaderUsesOpenedDescriptorAfterReplacement(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))

	file, err := openSecureLocalAuthorizedKeysFile(path, uint32(os.Geteuid()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	require.NoError(t, os.Rename(path, filepath.Join(directory, "opened-authorized_keys")))
	require.NoError(t, os.WriteFile(path, []byte("replacement"), 0600))

	actual, err := readSecureLocalAuthorizedKeysFile(file, path)
	require.NoError(t, err)
	require.Equal(t, []byte("original"), actual)
}

func TestSecureLocalAuthorizedKeysReaderEnforcesSizeLimitAfterOpen(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte("key"), 0600))

	file, err := openSecureLocalAuthorizedKeysFile(path, uint32(os.Geteuid()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	require.NoError(t, os.Truncate(path, maximumLocalAuthorizedKeysFileSize+1))

	_, err = readSecureLocalAuthorizedKeysFile(file, path)
	require.ErrorContains(t, err, "size limit")
}

func TestSecureLocalAuthorizedKeysReaderRejectsOversizedFileBeforeRead(t *testing.T) {
	directory := newSecureLocalAuthorizedKeysTestDirectory(t)
	path := filepath.Join(directory, "authorized_keys")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	require.NoError(t, os.Truncate(path, maximumLocalAuthorizedKeysFileSize+1))

	_, err := secureLocalAuthorizedKeysReader(user.Id(os.Geteuid()))(path)
	require.ErrorContains(t, err, "size limit")
}

func newSecureLocalAuthorizedKeysTestDirectory(t *testing.T) string {
	t.Helper()

	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	directory, err := os.MkdirTemp(workingDirectory, ".authorized-keys-test-")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(directory, 0700))
	t.Cleanup(func() {
		_ = os.Chmod(directory, 0700)
		_ = os.RemoveAll(directory)
	})
	return directory
}
