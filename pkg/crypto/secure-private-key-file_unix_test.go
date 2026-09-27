//go:build unix

package crypto

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type securePrivateKeyFileInfoWithStat struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (this securePrivateKeyFileInfoWithStat) Sys() any {
	return &this.stat
}

func TestSecurePrivateKeyFileRejectsDifferentUnixOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	info, err := os.Stat(path)
	require.NoError(t, err)
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Geteuid() + 1)

	err = validateSecurePrivateKeyFile(path, nil, securePrivateKeyFileInfoWithStat{FileInfo: info, stat: stat})
	require.ErrorContains(t, err, "owned by user")
}

func TestLoadSecurePrivateKeyFileRejectsUnixSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "identity")
	require.NoError(t, os.WriteFile(target, []byte("key"), 0600))
	require.NoError(t, os.Symlink(target, path))

	_, err := LoadSecurePrivateKeyFile(path, 1<<20)
	require.ErrorContains(t, err, "not a regular file")
}

func TestLoadSecurePrivateKeyFileRejectsUnixHardLink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "identity")
	alias := filepath.Join(directory, "alias")
	require.NoError(t, os.WriteFile(path, []byte("key"), 0600))
	require.NoError(t, os.Link(path, alias))

	_, err := LoadSecurePrivateKeyFile(path, 1<<20)
	require.ErrorContains(t, err, "hard links")
}
