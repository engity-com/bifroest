//go:build unix

package audit

func replaceNativeHeadFile(source, target string) error {
	return replaceJournalFile(source, target)
}
