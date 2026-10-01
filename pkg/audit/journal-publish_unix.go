//go:build unix

package audit

import (
	goerrors "errors"
	"io/fs"
	"os"
)

func publishJournalFile(source, target string) error {
	if _, err := os.Stat(target); err == nil {
		return fs.ErrExist
	} else if !goerrors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.Rename(source, target)
}
