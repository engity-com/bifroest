package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
)

func TestEventFilterMatchesNameFlowAndInclusiveTimes(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	records := []bfAudit.VerifiedRecord{
		{RecordedAt: start, Event: bfAudit.Event{Name: "login", Flow: "public"}},
		{RecordedAt: start.Add(time.Minute), Event: bfAudit.Event{Name: "login", Flow: "admin"}},
		{RecordedAt: start.Add(2 * time.Minute), Event: bfAudit.Event{Name: "logout", Flow: "admin"}},
		{RecordedAt: start.Add(3 * time.Minute), Event: bfAudit.Event{Name: "login", Flow: "admin"}},
	}
	filter := EventFilter{Name: "login", Flow: "admin", Since: start.Add(time.Minute), Limit: 1}
	_, err := filter.selection(false)
	require.ErrorContains(t, err, "--with-sensitive")
	selection, err := filter.selection(true)
	require.NoError(t, err)
	require.Equal(t, uint(1), selection.Limit)
	for i, want := range []bool{false, true, false, true} {
		require.Equal(t, want, selection.Matches(records[i]))
	}

	filter.Until = start.Add(time.Minute)
	selection, err = filter.selection(true)
	require.NoError(t, err)
	for i, want := range []bool{false, true, false, false} {
		require.Equal(t, want, selection.Matches(records[i]))
	}
}
