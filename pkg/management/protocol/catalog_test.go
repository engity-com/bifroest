package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCatalogReadCursorsBindOperationAndAuditlogWithoutChangingLegacyFilters(t *testing.T) {
	id := "9c77b24c-62f4-44c2-aea3-771c75e5a107"
	for _, operation := range []ReadOperation{ListFlows, ListSessions} {
		request, err := (ReadRequest{Operation: operation}).Normalize()
		require.NoError(t, err)
		legacy, err := json.Marshal(struct{ Flow, User, State string }{request.Flow, request.User, request.State})
		require.NoError(t, err)
		require.Equal(t, sha256.Sum256(legacy), request.filter())
	}
	request, err := (ReadRequest{Operation: ListRecordings, Auditlog: "production"}).Normalize()
	require.NoError(t, err)
	request.After = (RecordingPageCursor{Auditlog: "production", Filter: request.RecordingFilter(),
		ActorFlow: "management", ActorSession: id, StartedAt: "2026-01-01T00:00:00Z", ID: id,
		Expires: 1, MAC: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}).Token()
	name, selected, err := request.Cursor()
	require.NoError(t, err)
	require.Equal(t, "production", name)
	require.Equal(t, id, selected)
	for _, change := range []func(*ReadRequest){
		func(r *ReadRequest) { r.Auditlog = "other" },
		func(r *ReadRequest) { r.Operation = ListAuditlogs; r.Auditlog = "" },
		func(r *ReadRequest) { r.Flow = "work" },
		func(r *ReadRequest) { r.User = "alice" },
		func(r *ReadRequest) { r.State = "all" },
		func(r *ReadRequest) { r.ID = id },
	} {
		changed := request
		change(&changed)
		_, err := changed.Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
	for _, operation := range []ReadOperation{ListAuditlogs, ListRecordings} {
		base := ReadRequest{Operation: operation}
		if operation == ListRecordings {
			base.Auditlog = "production"
		}
		for _, limit := range []int{-1, MaximumPageSize + 1} {
			bad := base
			bad.Limit = limit
			_, err := bad.Normalize()
			require.ErrorIs(t, err, ErrRequest)
		}
		for _, position := range [][2]string{{"../private", ""}, {"production", "not-an-id"}, {"other", id}} {
			bad := base
			bad.After = bad.Next(position[0], position[1])
			_, err := bad.Normalize()
			require.ErrorIs(t, err, ErrRequest)
		}
	}
	logs, err := (ReadRequest{Operation: ListAuditlogs}).Normalize()
	require.NoError(t, err)
	logs.After = logs.Next("production", "")
	_, err = logs.Normalize()
	require.NoError(t, err)
	bad := logs
	bad.Auditlog = "production"
	_, err = bad.Normalize()
	require.ErrorIs(t, err, ErrRequest)
	raw, err := base64.RawURLEncoding.DecodeString(logs.After[5:])
	require.NoError(t, err)
	logs.After = "bmp1." + base64.RawURLEncoding.EncodeToString(append(raw, '\n'))
	_, err = logs.Normalize()
	require.ErrorIs(t, err, ErrRequest)
}

func TestRecordingCatalogFilterValidationAndCursorMixup(t *testing.T) {
	base, err := (ReadRequest{Operation: ListRecordings, Auditlog: "default"}).Normalize()
	require.NoError(t, err)
	require.Equal(t, "all", base.Status)
	require.Equal(t, "started-desc", base.Sort)
	for _, change := range []func(*ReadRequest){
		func(r *ReadRequest) { r.Flow = strings.Repeat("é", 128) },
		func(r *ReadRequest) { r.User = "\xff" },
		func(r *ReadRequest) { r.Target = "host\nprivate" },
		func(r *ReadRequest) { r.Status = "running" },
		func(r *ReadRequest) { r.Sort = "uuid" },
		func(r *ReadRequest) { r.StartedFrom = "2026-02-30T00:00:00Z" },
		func(r *ReadRequest) { r.StartedFrom = "2026-01-01" },
		func(r *ReadRequest) { r.StartedFrom = "2026-01-01T00:00:00+00:00" },
		func(r *ReadRequest) { r.StartedFrom = "2026-01-01T00:00:00,5Z" },
		func(r *ReadRequest) { r.StartedFrom = "2026-01-02T00:00:00Z"; r.StartedUntil = "2026-01-01T00:00:00Z" },
	} {
		request := base
		change(&request)
		_, err := request.Normalize()
		require.ErrorIs(t, err, ErrRequest, "%+v", request)
	}
	base.StartedFrom, base.StartedUntil = "2026-01-01T00:00:00.000000001Z", "2026-01-01T00:00:00.000000001Z"
	base, err = base.Normalize()
	require.NoError(t, err)
	id := "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	base.After = (RecordingPageCursor{Auditlog: base.Auditlog, Filter: base.RecordingFilter(), ActorFlow: "management", ActorSession: id,
		StartedAt: base.StartedFrom, ID: id, Expires: 1, MAC: base64.RawURLEncoding.EncodeToString(make([]byte, 32))}).Token()
	for _, change := range []func(*ReadRequest){
		func(r *ReadRequest) { r.Flow = "other" },
		func(r *ReadRequest) { r.User = "alice" },
		func(r *ReadRequest) { r.Target = "host" },
		func(r *ReadRequest) { r.Status = "failed" },
		func(r *ReadRequest) { r.StartedUntil = "2026-01-02T00:00:00Z" },
		func(r *ReadRequest) { r.Limit = 1 },
	} {
		request := base
		change(&request)
		_, err := request.Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
	for _, operation := range []ReadOperation{ListFlows, ListSessions, ListAuditlogs, ShowVersion} {
		_, err := (ReadRequest{Operation: operation, Status: "completed"}).Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
}
