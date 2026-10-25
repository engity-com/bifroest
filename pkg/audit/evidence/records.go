package evidence

import (
	"encoding/json"
	"io"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/errors"
)

type VerifiedRecord struct {
	Auditlog           string     `json:"auditlog"`
	ProducerId         ProducerId `json:"producerId"`
	SegmentSequence    uint64     `json:"segmentSequence"`
	SegmentRecordIndex uint64     `json:"segmentRecordIndex"`
	Id                 uuid.UUID  `json:"id"`
	RecordedAt         time.Time  `json:"recordedAt"`
	Event              Event      `json:"event"`
	PreviousHash       string     `json:"previousHash"`
	Hash               string     `json:"hash"`
}

const (
	MaxMaterializedAuditRecords = 250_000
	MaxMaterializedAuditBytes   = 64 << 20
)

// ConsumeRecordBudget preserves the shared native materialization limits.
// Integrity-only traversal counts every record without charging retained bytes.
func ConsumeRecordBudget(records uint64, retainedBytes, payloadBytes int64, materialize bool) (uint64, int64, error) {
	if records == math.MaxUint64 || payloadBytes < 0 || retainedBytes < 0 {
		return records, retainedBytes, errors.System.Newf("invalid or overflowing verified audit counters")
	}
	if materialize && (records >= MaxMaterializedAuditRecords || payloadBytes > MaxMaterializedAuditBytes-retainedBytes) {
		return records, retainedBytes, materializationError()
	}
	if materialize {
		retainedBytes += payloadBytes
	}
	return records + 1, retainedBytes, nil
}

func materializationError() error {
	return errors.System.Newf("verified audit output exceeds the materialization limit of %d records or %d bytes", MaxMaterializedAuditRecords, MaxMaterializedAuditBytes)
}

// RecordSelection limits retained output, never the records being verified.
// Matches receives records after the source's sensitive-data policy is applied.
// A nil Matches predicate selects every record.
type RecordSelection struct {
	Matches func(VerifiedRecord) bool
	Limit   uint // Newest matching records in verification order; zero means all.
}

type selectedRecord struct {
	record VerifiedRecord
	bytes  int64
}

type SelectedRecords struct {
	selection RecordSelection
	records   []selectedRecord
	next      int
	bytes     int64
}

func NewSelectedRecords(selection RecordSelection) *SelectedRecords {
	return &SelectedRecords{selection: selection}
}

func (this *SelectedRecords) Add(record VerifiedRecord, payloadBytes int64) error {
	if this.selection.Matches != nil && !this.selection.Matches(record) {
		return nil
	}
	replace := this.selection.Limit > 0 && uint(len(this.records)) == this.selection.Limit
	retainedBytes := this.bytes
	if replace {
		retainedBytes -= this.records[this.next].bytes
	}
	if payloadBytes < 0 || !replace && len(this.records) >= MaxMaterializedAuditRecords || payloadBytes > MaxMaterializedAuditBytes-retainedBytes {
		return materializationError()
	}
	selected := selectedRecord{record: record, bytes: payloadBytes}
	if replace {
		this.records[this.next] = selected
		this.next = (this.next + 1) % len(this.records)
	} else {
		this.records = append(this.records, selected)
	}
	this.bytes = retainedBytes + payloadBytes
	return nil
}

func (this *SelectedRecords) Clone() *SelectedRecords {
	if this == nil {
		return nil
	}
	result := *this
	result.records = append([]selectedRecord(nil), this.records...)
	return &result
}

func (this *SelectedRecords) Records() []VerifiedRecord {
	if this == nil {
		return nil
	}
	result := make([]VerifiedRecord, 0, len(this.records))
	for _, record := range this.records[this.next:] {
		result = append(result, record.record)
	}
	for _, record := range this.records[:this.next] {
		result = append(result, record.record)
	}
	return result
}

type RecordOrder string

const (
	RecordOrderChain         RecordOrder = "chain"
	RecordOrderChronological RecordOrder = "chronological"
)

// ExportVerifiedRecords preserves the established JSONL envelope and ordering.
// The caller supplies only records released by successful full-source checks.
func ExportVerifiedRecords(output io.Writer, input []VerifiedRecord, order RecordOrder, withSensitive bool) error {
	records := append([]VerifiedRecord(nil), input...)
	switch order {
	case RecordOrderChain:
	case RecordOrderChronological:
		sort.SliceStable(records, func(left, right int) bool {
			return lessVerifiedRecord(records[left], records[right])
		})
	default:
		return errors.Config.Newf("unsupported audit record order %q", order)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if !withSensitive {
			record.Event = Event{Name: record.Event.Name, Domain: record.Event.Domain, Outcome: record.Event.Outcome}
		}
		if err := encoder.Encode(record); err != nil {
			return errors.System.Newf("cannot export verified audit record: %w", err)
		}
	}
	return nil
}

func lessVerifiedRecord(left, right VerifiedRecord) bool {
	if !left.RecordedAt.Equal(right.RecordedAt) {
		return left.RecordedAt.Before(right.RecordedAt)
	}
	if left.Auditlog != right.Auditlog {
		return left.Auditlog < right.Auditlog
	}
	if left.ProducerId != right.ProducerId {
		return left.ProducerId.String() < right.ProducerId.String()
	}
	if left.SegmentSequence != right.SegmentSequence {
		return left.SegmentSequence < right.SegmentSequence
	}
	if left.SegmentRecordIndex != right.SegmentRecordIndex {
		return left.SegmentRecordIndex < right.SegmentRecordIndex
	}
	return left.Id.String() < right.Id.String()
}
