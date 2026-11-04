package service

import (
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/stretchr/testify/require"
)

func TestManagementGridSortAndSearchAreServerSideAndCursorBound(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		base := conf.Flows[0]
		conf.Flows = nil
		for _, name := range []string{"z", "a", "m", "aa"} {
			flow := base
			flow.Name = configuration.FlowName(name)
			flow.DiscoverAsSlug = ""
			conf.Flows = append(conf.Flows, flow)
		}
	})
	var names []string
	after := ""
	for range 4 {
		code, result, body := managementWebRead(t, handler, token, "flows/list", map[string]string{"limit": "1", "sort": "name-desc", "after": after, "query": "MANAGEMENT"})
		require.Equal(t, 200, code, body)
		require.Len(t, result.Flows.Items, 1)
		names = append(names, result.Flows.Items[0].Name)
		after = result.Flows.Next
		if after != "" {
			code, _, _ = managementWebRead(t, handler, token, "flows/list", map[string]string{"limit": "1", "sort": "name-asc", "after": after, "query": "MANAGEMENT"})
			require.Equal(t, 400, code)
			code, _, _ = managementWebRead(t, handler, token, "flows/list", map[string]string{"limit": "1", "sort": "name-desc", "after": after, "query": "different"})
			require.Equal(t, 400, code)
		}
	}
	require.Equal(t, []string{"z", "m", "aa", "a"}, names)
	require.Empty(t, after)
	code, result, body := managementWebRead(t, handler, token, "flows/list", map[string]string{"query": "aa management"})
	require.Equal(t, 200, code, body)
	require.Len(t, result.Flows.Items, 1)
	require.Equal(t, "aa", result.Flows.Items[0].Name)
	for _, route := range []string{"flows/list", "sessions/list", "auditlogs/list"} {
		code, _, _ = managementWebRead(t, handler, token, route, map[string]string{"query": "bad\nquery"})
		require.Equal(t, 400, code)
		code, _, _ = managementWebRead(t, handler, token, route, map[string]string{"sort": "unsupported-desc"})
		require.Equal(t, 400, code)
	}
}

func TestManagementRecordingGridAscendsAcrossCursorPagesAndBindsSearch(t *testing.T) {
	svc, handler, _, token := managementWebFixture(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		id     int
		offset time.Duration
	}{{3, time.Second}, {1, 0}, {4, 2 * time.Second}, {2, time.Second}} {
		catalogRecordingWithContext(t, svc, "default", row.id, base.Add(row.offset), "grid-fixture", recording.CastStatusCompleted)
	}
	var ids []string
	after := ""
	for range 4 {
		fields := map[string]string{"auditlog": "default", "limit": "1", "sort": "started-asc", "query": "GRID-fixture completed", "after": after}
		code, result, body := managementWebRead(t, handler, token, "recordings/list", fields)
		require.Equal(t, 200, code, body)
		require.Len(t, result.Recordings.Items, 1)
		ids = append(ids, result.Recordings.Items[0].ID)
		after = result.Recordings.Next
		if after != "" {
			fields["after"] = after
			fields["sort"] = "started-desc"
			code, _, _ = managementWebRead(t, handler, token, "recordings/list", fields)
			require.Equal(t, 400, code)
			fields["sort"] = "started-asc"
			fields["query"] = "other"
			code, _, _ = managementWebRead(t, handler, token, "recordings/list", fields)
			require.Equal(t, 400, code)
		}
	}
	require.Equal(t, []string{"00000001-0000-4000-8000-000000000000", "00000002-0000-4000-8000-000000000000", "00000003-0000-4000-8000-000000000000", "00000004-0000-4000-8000-000000000000"}, ids)
	require.Empty(t, after)
}

func TestManagementGridOrderingHandlesPrefixesAndUnicode(t *testing.T) {
	for _, pair := range [][2]string{{"a", "aa"}, {"aa", "b"}, {"b", "ä"}, {"ä", "ö"}} {
		require.Less(t, managementGridKey(pair[0], false), managementGridKey(pair[1], false))
		require.Greater(t, managementGridKey(pair[0], true), managementGridKey(pair[1], true))
	}
	require.True(t, managementSearch(" ALICE   OPS ", "alice", "ops"))
	require.False(t, managementSearch("alice unavailable", "alice", "ops"))
}
