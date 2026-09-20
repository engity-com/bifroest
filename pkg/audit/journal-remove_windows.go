//go:build windows

package audit

import (
	"io/fs"
	"os"

	"github.com/engity-com/bifroest/pkg/errors"
)

func removeTemporaryJournalFile(path string) error {
	tombstone := path + remoteArtifactReceiptCleanupSuffix
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if err := os.Remove(tombstone); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	} else if err != nil {
		return err
	}
	if err := replaceJournalFile(path, tombstone); err != nil {
		return err
	}
	return os.Remove(tombstone)
}
