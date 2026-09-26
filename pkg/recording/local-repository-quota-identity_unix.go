//go:build unix

package recording

import (
	"os"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localInventoryFileIdentity struct {
	device uint64
	inode  uint64
}

func inventoryLocalFileIdentity(_ string, info os.FileInfo) (localInventoryFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return localInventoryFileIdentity{}, errors.System.Newf("cannot identify local recording file")
	}
	return localInventoryFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}
