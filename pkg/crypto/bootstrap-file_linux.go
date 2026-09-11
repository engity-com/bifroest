//go:build linux

package crypto

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func installBootstrapFile(temporary, target string, force bool) error {
	var err error
	if force {
		err = os.Rename(temporary, target)
	} else {
		err = unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
			if err = os.Link(temporary, target); err == nil {
				err = os.Remove(temporary)
			}
		}
	}
	if err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
