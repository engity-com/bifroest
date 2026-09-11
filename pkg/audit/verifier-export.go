package audit

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/engity-com/bifroest/pkg/errors"
)

type RecordOrder string

const (
	RecordOrderChain         RecordOrder = "chain"
	RecordOrderChronological RecordOrder = "chronological"
)

func (this *Verification) ExportJSONLines(output io.Writer, order RecordOrder) error {
	if this == nil {
		return nil
	}
	records := this.Records()
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
