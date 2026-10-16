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

func FilterEvents(records []bfAudit.VerifiedRecord, filter EventFilter, sensitive bool) ([]bfAudit.VerifiedRecord, error) {
	if filter.Flow != "" && !sensitive {
		return nil, fmt.Errorf("filtering audit events by flow requires --with-sensitive")
	}
	matching := make([]bfAudit.VerifiedRecord, 0, len(records))
	for _, record := range records {
		if filter.Name != "" && record.Event.Name != filter.Name ||
			filter.Flow != "" && record.Event.Flow != filter.Flow ||
			!filter.Since.IsZero() && record.RecordedAt.Before(filter.Since) ||
			!filter.Until.IsZero() && record.RecordedAt.After(filter.Until) {
			continue
		}
		matching = append(matching, record)
	}
	if filter.Limit > 0 && uint(len(matching)) > filter.Limit {
		matching = matching[len(matching)-int(filter.Limit):]
	}
	return matching, nil
}
