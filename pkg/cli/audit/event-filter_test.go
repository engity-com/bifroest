package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
)

func TestEventFilterKeepsNewestMatchingRecordsWithoutOverflow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	records := []bfAudit.VerifiedRecord{
		{RecordedAt: start, Event: bfAudit.Event{Name: "login", Flow: "public"}},
		{RecordedAt: start.Add(time.Minute), Event: bfAudit.Event{Name: "login", Flow: "admin"}},
		{RecordedAt: start.Add(2 * time.Minute), Event: bfAudit.Event{Name: "logout", Flow: "admin"}},
		{RecordedAt: start.Add(3 * time.Minute), Event: bfAudit.Event{Name: "login", Flow: "admin"}},
	}
	filter := EventFilter{Name: "login", Flow: "admin", Since: start.Add(time.Minute), Limit: 1}
	_, err := FilterEvents(records, filter, false)
	require.ErrorContains(t, err, "--with-sensitive")
	selected, err := FilterEvents(records, filter, true)
	require.NoError(t, err)
	require.Len(t, selected, 1)
	require.Equal(t, start.Add(3*time.Minute), selected[0].RecordedAt)

	filter.Limit = ^uint(0)
	selected, err = FilterEvents(records, filter, true)
	require.NoError(t, err)
	require.Len(t, selected, 2)
}
