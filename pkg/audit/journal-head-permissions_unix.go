//go:build unix

package audit

import "os"

func protectJournalHead(path string, file *os.File) error {
	return sealJournalFile(path, file)
}

func openJournalHead(path string) (*os.File, error) {
	return openSealedJournal(path)
}
