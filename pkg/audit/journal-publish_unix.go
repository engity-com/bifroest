//go:build unix

package audit

import (
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/errors"
)

func publishJournalFile(source, target string) error {
	if err := os.Link(source, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			sourceInfo, sourceErr := os.Stat(source)
			targetInfo, targetErr := os.Stat(target)
			if sourceErr == nil && targetErr == nil && os.SameFile(sourceInfo, targetInfo) {
				return os.Remove(source)
			}
		}
		return err
	}
	if err := syncJournalDirectory(filepath.Dir(source)); err != nil {
		return err
	}
	return os.Remove(source)
}
