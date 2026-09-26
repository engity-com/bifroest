//go:build unix

package audit

import "os"

func removeTemporaryJournalFile(path string) error {
	return os.Remove(path)
}
