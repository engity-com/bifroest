package protocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadRequestCanonicalCursorIsSelectorNotCredential(t *testing.T) {
	request, err := (ReadRequest{Operation: ListSessions, Flow: "work", User: "alice"}).Normalize()
	require.NoError(t, err)
	require.Equal(t, "active", request.State)
	require.Equal(t, MaximumPageSize, request.Limit)
	id := "9c77b24c-62f4-44c2-aea3-771c75e5a107"
	request.After = request.Next("work", id)
	flow, selected, err := request.Cursor()
	require.NoError(t, err)
	require.Equal(t, "work", flow)
	require.Equal(t, id, selected)
	for _, change := range []func(*ReadRequest){func(r *ReadRequest) { r.User = "bob" }, func(r *ReadRequest) { r.Flow = "other" }, func(r *ReadRequest) { r.State = "all" }, func(r *ReadRequest) { r.Operation = ListFlows }} {
		copy := request
		change(&copy)
		_, err := copy.Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
	encoded, _ := base64.RawURLEncoding.DecodeString(request.After[5:])
	for _, raw := range []string{string(encoded) + "\n", strings.Replace(string(encoded), `"flow":"work"`, `"flow":"work","extra":null`, 1)} {
		copy := request
		copy.After = "bmp1." + base64.RawURLEncoding.EncodeToString([]byte(raw))
		_, err := copy.Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
}

func TestReadRequestRejectsCommandsUnboundedPagesAndBadSelectors(t *testing.T) {
	for _, request := range []ReadRequest{{Operation: "session dispose"}, {Operation: ListFlows, Limit: MaximumPageSize + 1}, {Operation: ListSessions, State: "expired"}, {Operation: ListSessions, User: "alice\n"}, {Operation: ListFlows, After: "not-a-cursor"}, {Operation: ShowSession, Flow: "work", ID: "../id"}, {Operation: ShowSession, Flow: "work", ID: "00000000-0000-0000-0000-000000000000"}, {Operation: ListFlows, User: "alice"}} {
		_, err := request.Normalize()
		require.ErrorIs(t, err, ErrRequest)
	}
}
