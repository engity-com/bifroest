package service

import (
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func TestManagementColumnFiltersOperateBeforePaginationAndBindTheRealCursor(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		base := conf.Flows[0]
		conf.Flows = nil
		for _, name := range []string{"ops-z", "other", "ops-a"} {
			flow := base
			flow.Name = configuration.FlowName(name)
			flow.DiscoverAsSlug = ""
			conf.Flows = append(conf.Flows, flow)
		}
	})
	fields := map[string]string{"filterField": "name", "filterOperator": "startsWith", "filterValue": "OPS-", "limit": "1"}
	code, result, body := managementWebRead(t, handler, token, "flows/list", fields)
	require.Equal(t, 200, code, body)
	require.Len(t, result.Flows.Items, 1)
	require.Equal(t, "ops-a", result.Flows.Items[0].Name)
	require.NotEmpty(t, result.Flows.Next)
	fields["after"] = result.Flows.Next
	code, result, body = managementWebRead(t, handler, token, "flows/list", fields)
	require.Equal(t, 200, code, body)
	require.Len(t, result.Flows.Items, 1)
	require.Equal(t, "ops-z", result.Flows.Items[0].Name)
	require.Empty(t, result.Flows.Next)
	fields["filterValue"] = "other"
	code, _, _ = managementWebRead(t, handler, token, "flows/list", fields)
	require.Equal(t, 400, code)
	for _, invalid := range []map[string]string{{"filterField": "name"}, {"filterField": "privateKey", "filterOperator": "isEmpty", "filterValue": ""}, {"filterField": "name", "filterOperator": "regexp", "filterValue": ".*"}} {
		code, _, _ = managementWebRead(t, handler, token, "flows/list", invalid)
		require.Equal(t, 400, code)
	}
}

func TestManagementColumnFilterDoesNotInferEmptyOrNegativeWithheldFields(t *testing.T) {
	svc, handler, _, _ := managementWebFixture(t)
	token := forcedManagementWebLogin(t, svc, handler, "session ls --user=alice --format=table")
	for _, operator := range []string{"isEmpty", "isNotEmpty", "doesNotContain", "doesNotEqual"} {
		value := ""
		if operator == "doesNotContain" || operator == "doesNotEqual" {
			value = "private"
		}
		code, result, body := managementWebRead(t, handler, token, "sessions/list", map[string]string{"filterField": "remote", "filterOperator": operator, "filterValue": value})
		require.Equal(t, 200, code, body)
		require.Empty(t, result.Sessions.Items)
	}
}
