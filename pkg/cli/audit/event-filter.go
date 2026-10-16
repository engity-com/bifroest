package audit

import (
	"fmt"
	"time"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
)

type EventFilter struct {
	Name  string
	Flow  string
	Since time.Time
	Until time.Time
	Limit uint
}

func (this EventFilter) selection(sensitive bool) (bfAudit.RecordSelection, error) {
	if this.Flow != "" && !sensitive {
		return bfAudit.RecordSelection{}, fmt.Errorf("filtering audit events by flow requires --with-sensitive")
	}
	return bfAudit.RecordSelection{Matches: this.matches, Limit: this.Limit}, nil
}

func (this EventFilter) matches(record bfAudit.VerifiedRecord) bool {
	return (this.Name == "" || record.Event.Name == this.Name) &&
		(this.Flow == "" || record.Event.Flow == this.Flow) &&
		(this.Since.IsZero() || !record.RecordedAt.Before(this.Since)) &&
		(this.Until.IsZero() || !record.RecordedAt.After(this.Until))
}
