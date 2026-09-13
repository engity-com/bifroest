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
