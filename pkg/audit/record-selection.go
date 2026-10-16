package audit

import "github.com/engity-com/bifroest/pkg/errors"

// RecordSelection limits retained output, never the records being verified.
// Matches receives records after the source's sensitive-data policy is applied.
// A nil Matches predicate selects every record.
type RecordSelection struct {
	Matches func(VerifiedRecord) bool
	Limit   uint // Newest matching records in verification order; zero means all.
}

type selectedVerifiedRecord struct {
	record VerifiedRecord
	bytes  int64
}

type verifiedRecordSelection struct {
	selection RecordSelection
	records   []selectedVerifiedRecord
	next      int
	bytes     int64
}

func (this *verifiedRecordSelection) add(record VerifiedRecord, payloadBytes int64) error {
	if this.selection.Matches != nil && !this.selection.Matches(record) {
		return nil
	}
	replace := this.selection.Limit > 0 && uint(len(this.records)) == this.selection.Limit
	retainedBytes := this.bytes
	if replace {
		retainedBytes -= this.records[this.next].bytes
	}
	if !replace && len(this.records) >= maxMaterializedVerifiedRecords || payloadBytes > maxMaterializedVerifiedBytes-retainedBytes {
		return errors.System.Newf("verified audit output exceeds the materialization limit of %d records or %d bytes", maxMaterializedVerifiedRecords, maxMaterializedVerifiedBytes)
	}
	selected := selectedVerifiedRecord{record: record, bytes: payloadBytes}
	if replace {
		this.records[this.next] = selected
		this.next = (this.next + 1) % len(this.records)
	} else {
		this.records = append(this.records, selected)
	}
	this.bytes = retainedBytes + payloadBytes
	return nil
}

func (this *verifiedRecordSelection) clone() *verifiedRecordSelection {
	result := *this
	result.records = append([]selectedVerifiedRecord(nil), this.records...)
	return &result
}

func (this *verifiedRecordSelection) materialize() []VerifiedRecord {
	result := make([]VerifiedRecord, 0, len(this.records))
	for _, record := range this.records[this.next:] {
		result = append(result, record.record)
	}
	for _, record := range this.records[:this.next] {
		result = append(result, record.record)
	}
	return result
}
