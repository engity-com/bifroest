package service

import (
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/stretchr/testify/require"
)

func TestGridColumnFiltersUseTypedNativeOperatorsAndCannotSelectPrivateFields(t *testing.T) {
	type GridFilter = protocol.GridFilter
	type GridValue = protocol.GridValue
	const ListFlows = protocol.ListFlows
	const ListSessions = protocol.ListSessions
	const ListRecordings = protocol.ListRecordings
	GridText := protocol.GridText
	GridNumber := protocol.GridNumber
	GridTime := protocol.GridTime
	ErrRequest := protocol.ErrRequest
	for _, test := range []struct {
		filter GridFilter
		value  GridValue
		want   bool
	}{
		{GridFilter{Field: "name", Operator: "contains", Value: "OPS"}, GridText("my-ops-flow"), true},
		{GridFilter{Field: "name", Operator: "equals", Value: "cafe"}, GridText("Café"), true},
		{GridFilter{Field: "name", Operator: "doesNotContain", Value: "[.*]"}, GridText("literal text"), true},
		{GridFilter{Field: "name", Operator: "startsWith", Value: "ops"}, GridText("my-ops"), false},
		{GridFilter{Field: "name", Operator: "isAnyOf", Value: `["other","OPS"]`}, GridText("ops"), true},
	} {
		require.NoError(t, test.filter.Validate(ListFlows))
		require.Equal(t, test.want, managementGridPredicate(&test.filter, ListFlows)(map[string]GridValue{"name": test.value}))
	}
	for _, filter := range []GridFilter{{Field: "privateKey", Operator: "contains", Value: "secret"}, {Field: "name", Operator: "regex", Value: ".*"}, {Field: "name", Operator: "isAnyOf", Value: `[1]`}, {Field: "name", Operator: "isAnyOf", Value: "[]"}, {Field: "name", Operator: "isEmpty", Value: "value"}, {Field: "name", Operator: "contains", Value: "bad\nvalue"}} {
		require.ErrorIs(t, filter.Validate(ListFlows), ErrRequest)
	}
	for _, op := range []string{"isEmpty", "isNotEmpty", "doesNotContain", "doesNotEqual"} {
		value := ""
		if op == "doesNotContain" || op == "doesNotEqual" {
			value = "secret"
		}
		filter := GridFilter{Field: "remote", Operator: op, Value: value}
		require.NoError(t, filter.Validate(ListSessions))
		require.False(t, managementGridPredicate(&filter, ListSessions)(map[string]GridValue{}), "withheld metadata is unknown, never a negative/empty predicate oracle")
	}
	number := GridFilter{Field: "containerBytes", Operator: ">=", Value: "1024"}
	require.NoError(t, number.Validate(ListRecordings))
	require.True(t, managementGridPredicate(&number, ListRecordings)(map[string]GridValue{"containerBytes": GridNumber(1024)}))
	number.Value = "NaN"
	require.ErrorIs(t, number.Validate(ListRecordings), ErrRequest)
	minute := time.Date(2026, 11, 4, 10, 30, 0, 0, time.UTC)
	date := GridFilter{Field: "startedAt", Operator: "is", Value: minute.Format(time.RFC3339)}
	require.NoError(t, date.Validate(ListRecordings))
	require.True(t, managementGridPredicate(&date, ListRecordings)(map[string]GridValue{"startedAt": GridTime(minute.Add(37 * time.Second))}))
	date.Operator = "after"
	require.True(t, managementGridPredicate(&date, ListRecordings)(map[string]GridValue{"startedAt": GridTime(minute.Add(37 * time.Second))}))
}

func TestGridColumnFiltersAreBoundToTheirPaginationAndCopiedAtNormalization(t *testing.T) {
	type GridFilter = protocol.GridFilter
	type ReadRequest = protocol.ReadRequest
	const ListFlows = protocol.ListFlows
	ErrRequest := protocol.ErrRequest
	filter := &GridFilter{Field: "name", Operator: "contains", Value: "ops"}
	request, err := (ReadRequest{Operation: ListFlows, GridFilter: filter}).Normalize()
	require.NoError(t, err)
	cursor := request.Next("ops", " ")
	filter.Value = "changed"
	require.Equal(t, "ops", request.GridFilter.Value)
	request.After = cursor
	_, err = request.Normalize()
	require.ErrorIs(t, err, ErrRequest, "invalid cursor IDs remain invalid even with a new filter")
	request.After = request.Next("ops", "")
	_, err = request.Normalize()
	require.NoError(t, err)
	request.GridFilter = &GridFilter{Field: "name", Operator: "contains", Value: "different"}
	_, err = request.Normalize()
	require.ErrorIs(t, err, ErrRequest)
}
