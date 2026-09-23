//go:build windows

package audit

import (
	"os"

	"github.com/engity-com/bifroest/pkg/errors"
)

func secureJournalDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() {
		return errors.Config.Newf("%q is not a directory", path)
	}
	return nil
}

func secureJournalFile(path string, file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return errors.System.Newf("cannot inspect audit journal path %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return errors.Config.Newf("%q is not a regular file", path)
	}
	return nil
}

func sealJournalFile(path string, file *os.File) error {
	if err := file.Sync(); err != nil {
		return errors.System.Newf("cannot flush sealed audit segment %q: %w", path, err)
	}
	return nil
}
