package service

import (
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/uuidtext"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestManagementUUIDFiltersMatchBinaryNotCaseFoldedBase58(t *testing.T) {
	classic := "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	base := "7Xng23oeg4L1zHaZfeX6wB"
	other := "7xng23oeg4L1zHaZfeX6wB"
	a, err := uuidtext.Parse(base)
	require.NoError(t, err)
	b, err := uuidtext.Parse(other)
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	for _, field := range []string{"id", "sessionId"} {
		predicate := managementGridPredicate(&protocol.GridFilter{Field: field, Operator: "equals", Value: classic}, protocol.ListRecordings)
		require.True(t, predicate(map[string]protocol.GridValue{field: protocol.GridText(base)}))
		require.False(t, predicate(map[string]protocol.GridValue{field: protocol.GridText(other)}))
		require.False(t, predicate(map[string]protocol.GridValue{}))
		predicate = managementGridPredicate(&protocol.GridFilter{Field: field, Operator: "doesNotEqual", Value: base}, protocol.ListRecordings)
		require.False(t, predicate(map[string]protocol.GridValue{}))
		require.False(t, predicate(map[string]protocol.GridValue{field: protocol.GridText(classic)}))
		require.True(t, predicate(map[string]protocol.GridValue{field: protocol.GridText(other)}))
	}
}

func base58TestUUID(t *testing.T, text string) string {
	t.Helper()
	value, err := uuidtext.Parse(text)
	require.NoError(t, err)
	return uuidtext.Format(value)
}
func base58TestUUIDs(t *testing.T, texts ...string) []string {
	t.Helper()
	var result []string
	for _, text := range texts {
		result = append(result, base58TestUUID(t, text))
	}
	return result
}
