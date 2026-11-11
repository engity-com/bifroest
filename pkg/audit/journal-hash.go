package audit

import "github.com/engity-com/bifroest/pkg/audit/evidence"

type journalHash = evidence.Hash

func hashJournalBytes(domain string, content []byte) journalHash {
	return evidence.HashBytes(domain, content)
}
