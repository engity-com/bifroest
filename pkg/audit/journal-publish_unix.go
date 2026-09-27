//go:build unix

package audit

import (
	"os"
)

func publishJournalFile(source, target string) error {
	if err := os.Link(source, target); err != nil {
		return err
	}
	return os.Remove(source)
}
