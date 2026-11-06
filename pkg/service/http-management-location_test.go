package service

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func TestManagementLocationGrammarRetainsSlugBoundaryAndOnlyPermitsExplicitPublicSelectors(t *testing.T) {
	const id = "34e34ab8-7457-4d88-a5e4-c57791775c3a"
	for _, slug := range []string{"", "Admin", "team/Admin"} {
		prefix := "/"
		if slug != "" {
			prefix += slug + "/"
		}
		prefix += "admin"
		for _, suffix := range []string{"", "/version", "/sessions", "/sessions/docker", "/sessions/docker/" + id, "/recordings", "/recordings?auditlog=default&recording=" + id, "/recordings/docker", "/recordings/docker/" + id + "?auditlog=default", "/auditlogs", "/auditlogs/default", "/auditlogs/default/docker", "/auditlogs/default/-/" + id, "/auditlogs/default?event=" + id} {
			parsed, err := url.Parse(prefix + suffix)
			require.NoError(t, err)
			require.True(t, validManagementLocation(parsed, slug), prefix+suffix)
		}
		for _, suffix := range []string{"/", "/unknown", "/sessions/docker/invalid", "/sessions/%64ocker", "/sessions/docker/" + id + "/extra", "/auditlogs?event=" + id, "/recordings/docker/" + id + "?accessToken=secret", "/recordings/docker/" + id + "?auditlog=a&auditlog=b", "/version?"} {
			parsed, err := url.Parse(prefix + suffix)
			require.NoError(t, err)
			require.False(t, validManagementLocation(parsed, slug), prefix+suffix)
		}
	}
}

func TestManagementEntryRequiresARealEligibleManagementFlowAndPreservesWildcardAliasScope(t *testing.T) {
	_, handler, _ := webTestFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Name = "admin"
		conf.Flows[0].DiscoverAsSlug = "Work"
		conf.Flows[0].Requirement.Http.IncludedSlug = common.MustNewRegexp(".*")
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
	})
	for _, path := range []string{"/Work/admin", "/Work/admin/sessions/docker"} {
		response := webTestRequest(handler, "GET", "app.example.org", path, "", "")
		require.Equal(t, 200, response.Code, response.Body.String())
		var metadata struct {
			Scope webScope `json:"scope"`
		}
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metadata))
		require.Equal(t, "Work", metadata.Scope.Slug)
	}
	response := webTestRequest(handler, "GET", "app.example.org", "/unrelated-alias", "", "")
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
	response = webTestRequest(handler, "GET", "app.example.org", "/Work", "", "")
	require.Equal(t, 404, response.Code)
}

func TestManagementDeepEntryOnlyReturnsPublicDiscoveryAndKeepsTheOriginalAuthorizationScope(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) { conf.Flows[0].Title = "Management console" })
	response := webTestRequest(handler, "GET", "app.example.org", "/Work/recording-test/recordings/docker/34e34ab8-7457-4d88-a5e4-c57791775c3a?auditlog=default", "", "")
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
