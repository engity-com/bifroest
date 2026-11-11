package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionReadNormalizesOnlyItsExactDetailSelector(t *testing.T) {
	for _, detail := range []string{"", "long", "short"} {
		normalized, err := (ReadRequest{Operation: ShowVersion, VersionDetail: detail}).Normalize()
		require.NoError(t, err)
		if detail == "" {
			detail = "long"
		}
		require.Equal(t, detail, normalized.VersionDetail)
		require.Zero(t, normalized.Limit)
	}
	for _, request := range []ReadRequest{
		{Operation: ShowVersion, VersionDetail: "all"},
		{Operation: ShowVersion, Limit: 1},
		{Operation: ShowVersion, After: "cursor"},
		{Operation: ShowVersion, Flow: "work"},
		{Operation: ShowVersion, User: "alice"},
		{Operation: ShowVersion, State: "all"},
		{Operation: ShowVersion, ID: "9c77b24c-62f4-44c2-aea3-771c75e5a107"},
		{Operation: ShowVersion, Auditlog: "default"},
		{Operation: ListFlows, VersionDetail: "long"},
		{Operation: ListSessions, VersionDetail: "short"},
	} {
		_, err := request.Normalize()
		require.ErrorIs(t, err, ErrRequest, "%+v", request)
	}
}
