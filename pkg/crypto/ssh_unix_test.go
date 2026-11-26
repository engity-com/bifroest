//go:build unix

package crypto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestDoWithEachAuthorizedKeyForUser(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	file := filepath.Join(dir, "authorized_keys")
	require.NoError(t, os.WriteFile(file, ssh.MarshalAuthorizedKey(ed255191Pub), 0600))
	callback := func(candidate ssh.PublicKey, _ []AuthorizedKeyOption) (bool, bool, error) {
		require.Equal(t, ed255191Pub.Marshal(), candidate.Marshal())
		return true, false, nil
	}
	check := func(path string) (bool, error) {
		return DoWithEachAuthorizedKeyForUser[bool](uint32(os.Getuid()), true, callback, path)
	}

	accepted, err := check(file)
	require.NoError(t, err)
	require.True(t, accepted)

	require.NoError(t, os.Chmod(file, 0666))
	_, err = check(file)
	require.ErrorContains(t, err, "file writable by other users")
	require.NoError(t, os.Chmod(file, 0600))

	require.NoError(t, os.Chmod(dir, 0777))
	_, err = check(file)
	require.ErrorContains(t, err, "directory writable by other users")
	require.NoError(t, os.Chmod(dir, 0700))

	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(file, link))
	_, err = check(link)
	require.Error(t, err)

	parentLink := filepath.Join(dir, "parent-link")
	require.NoError(t, os.Symlink(dir, parentLink))
	_, err = check(filepath.Join(parentLink, "authorized_keys"))
	require.Error(t, err)

	fifo := filepath.Join(dir, "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	_, err = check(fifo)
	require.ErrorContains(t, err, "not a regular file")

	require.NoError(t, os.WriteFile(file, []byte(strings.Repeat("x", maxAuthorizedKeysFileSize+1)), 0600))
	_, err = check(file)
	require.ErrorContains(t, err, "exceed")
}
