package service

import (
	"encoding/json"
	"testing"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func TestManagementEntryRequiresARealEligibleManagementFlowAndPreservesWildcardAliasScope(t *testing.T) {
	_, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Name = "admin"
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp(".*")
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	for _, slug := range []string{"Work"} {
		response := webTestDiscovery(handler, slug)
		require.Equal(t, 200, response.Code, response.Body.String())
		var metadata struct {
			Scope webScope `json:"scope"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metadata))
		require.Equal(t, "Work", metadata.Scope.Slug)
	}
	response := webTestDiscovery(handler, "unrelated-alias")
	require.Equal(t, 200, response.Code)
	var metadata struct {
		Scope webScope `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metadata))
	require.Equal(t, "unrelated-alias", metadata.Scope.Slug)
	_, handler, _ = webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].DiscoverAsSlug = ""
		conf.Flows[0].Requirement.Http.IncludedSlug = common.Regexp{}
	})
	response = webTestDiscovery(handler, "Work")
	require.Equal(t, 404, response.Code)
}

func TestManagementDeepEntryOnlyReturnsPublicDiscoveryAndKeepsTheOriginalAuthorizationScope(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) { conf.Flows[0].Title = "Management console" })
	response := webTestDiscovery(handler, "Work")
	require.Equal(t, 200, response.Code, response.Body.String())
	var metadata struct {
		Scope webScope `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metadata))
	require.Equal(t, "Work", metadata.Scope.Slug)
	require.NotContains(t, response.Body.String(), "Management console")
	require.NotContains(t, response.Body.String(), "accessToken")
	require.NotContains(t, response.Body.String(), "recordings")
	response = webTestRequest(handler, "POST", "app.example.org", webAPI+"access", `{"slug":"Work"}`, token)
	require.Equal(t, 200, response.Code, response.Body.String())
	var access struct {
		Flow struct{ Name, Title string } `json:"flow"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &access))
	require.Equal(t, "recording-test", access.Flow.Name)
	require.Equal(t, "Management console", access.Flow.Title)
	response = webTestRequest(handler, "POST", "app.example.org", webAPI+"access?auditlog=default", `{"slug":"Work"}`, token)
	require.Equal(t, 400, response.Code)
}
