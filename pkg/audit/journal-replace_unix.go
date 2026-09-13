//go:build unix

package audit

import "os"

func replaceJournalFile(source, target string) error {
	return os.Rename(source, target)
}
