//go:build linux

package crypto

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func installPrivateKeyFile(temporary, target string) error {
	err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		if err = os.Link(temporary, target); err == nil {
			err = os.Remove(temporary)
		}
	}
	if err != nil {
		return err
	}
	return syncPrivateKeyDirectory(filepath.Dir(target))
}

func preparePrivateKeyFile(file *os.File, _ string) error { return file.Chmod(0400) }

func syncPrivateKeyDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
