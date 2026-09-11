//go:build unix

package audit

import (
	"os"
	"syscall"

	"github.com/engity-com/bifroest/pkg/errors"
)

func secureJournalDirectory(path string, info os.FileInfo) error {
	return validatePrivateJournalMode(path, info)
}

func secureJournalFile(path string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect audit journal path %q: %w", path, err)
	}
	if err := validatePrivateJournalMode(path, info); err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.System.Newf("cannot determine link count of %q", path)
	}
	if stat.Nlink != 1 {
		return errors.Config.Newf("%q has %d hard links instead of one", path, stat.Nlink)
	}
	return nil
}

func validatePrivateJournalMode(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.Config.Newf("%q has insecure permissions %04o", path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.System.Newf("cannot determine owner of %q", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.Config.Newf("%q is owned by user %d instead of %d", path, stat.Uid, os.Geteuid())
	}
	return nil
}
