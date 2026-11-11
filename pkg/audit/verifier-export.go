package audit

import (
	"io"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
)

type RecordOrder = evidence.RecordOrder

const (
	RecordOrderChain         = evidence.RecordOrderChain
	RecordOrderChronological = evidence.RecordOrderChronological
)

func (this *Verification) ExportJSONLines(output io.Writer, order RecordOrder) error {
	if this == nil {
		return nil
	}
	return evidence.ExportVerifiedRecords(output, this.records, order, this.withSensitive)
}
