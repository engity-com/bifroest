package audit

import "github.com/engity-com/bifroest/pkg/audit/evidence"

// RecordSelection limits retained output, never the records being verified.
// Matches receives records after the source's sensitive-data policy is applied.
// A nil Matches predicate selects every record.
type RecordSelection = evidence.RecordSelection

type verifiedRecordSelection struct {
	selection RecordSelection
	state     *evidence.SelectedRecords
}

func (this *verifiedRecordSelection) add(record VerifiedRecord, payloadBytes int64) error {
	if this.state == nil {
		this.state = evidence.NewSelectedRecords(this.selection)
	}
	return this.state.Add(record, payloadBytes)
}

func (this *verifiedRecordSelection) clone() *verifiedRecordSelection {
	result := *this
	result.state = this.state.Clone()
	return &result
}

func (this *verifiedRecordSelection) materialize() []VerifiedRecord {
	return this.state.Records()
}
