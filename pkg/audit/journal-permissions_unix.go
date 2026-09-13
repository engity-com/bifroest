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

func makeActiveJournalWritable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.System.Newf("cannot inspect active audit segment %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("active audit segment %q is not a regular file", path)
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
	if info.Mode().Perm() == journalFileMode {
		return nil
	}
	if info.Mode().Perm() != 0400 {
		return errors.Config.Newf("active audit segment %q has permissions %04o instead of 0600 or 0400", path, info.Mode().Perm())
	}
	if err := os.Chmod(path, journalFileMode); err != nil {
		return errors.System.Newf("cannot make active audit segment writable %q: %w", path, err)
	}
	return nil
}

func sealJournalFile(path string, file *os.File) error {
	if err := file.Chmod(0400); err != nil {
		return errors.System.Newf("cannot make sealed audit segment read-only %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush sealed audit segment metadata %q: %w", path, err)
	}
	return nil
}

func openSealedJournal(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open sealed audit segment %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot inspect sealed audit segment %q: %w", path, err)
	}
	if info.Mode().Perm() != 0400 {
		_ = file.Close()
		return nil, errors.Config.Newf("sealed audit segment %q has permissions %04o instead of 0400", path, info.Mode().Perm())
	}
	if err := secureJournalFile(path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
