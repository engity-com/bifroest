package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/management/access"
)

func TestEnvironmentManagementConfiguration(t *testing.T) {
	for _, test := range []struct {
		name          string
		configuration string
		permission    access.Permission
		allowed       bool
	}{
		{"default read", "type: management\n", access.MetricsRead, true},
		{"default redaction", "type: management\n", access.FlowsCredentials, false},
		{"explicit all", "type: management\naccess: true\n", access.FlowsCredentials, true},
		{"explicit none", "type: management\naccess: false\n", access.MetricsRead, false},
		{"empty object", "type: management\naccess: {}\n", access.MetricsRead, false},
		{"metrics only", "type: management\naccess: {metrics: true}\n", access.MetricsRead, true},
		{"metrics denies version", "type: management\naccess: {metrics: true}\n", access.VersionRead, false},
		{"explicit download", "type: management\naccess: {auditlogs: {download: true}}\n", access.AuditlogsDownload, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var configured Environment
			require.NoError(t, yaml.Unmarshal([]byte(test.configuration), &configured))
			management, ok := configured.V.(*EnvironmentManagement)
			require.True(t, ok)
			allowed, err := management.Access.Allows(test.permission, nil)
			require.NoError(t, err)
			require.Equal(t, test.allowed, allowed)
			encoded, err := yaml.Marshal(&configured)
			require.NoError(t, err)
			var restored Environment
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, configured.IsEqualTo(restored))
			require.Contains(t, management.FeatureFlags(), "management")
		})
	}
	var configured Environment
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nincludingCredentials: true\n"), &configured), "includingCredentials")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nincludingCredential: true\n"), &configured), "includingCredential")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nallowArtifactTransfer: true\n"), &configured), "allowArtifactTransfer")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nallowTrustUpdates: true\n"), &configured), "allowTrustUpdates")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nvariables:\n  SECRET: value\n"), &configured), "not supported")
	for _, source := range []string{"access: null", "access: &empty null", "nullValue: &empty null\naccess: *empty", "access: {metric: true}", "access: {metrics: null}", "access: []"} {
		require.Error(t, yaml.Unmarshal([]byte("type: management\n"+source+"\n"), &configured), source)
	}
	require.False(t, (&EnvironmentManagement{}).IsEqualTo(EnvironmentManagement{Access: access.Constant(true)}))
	require.False(t, (&EnvironmentManagement{}).IsEqualTo(EnvironmentManagement{Access: access.Constant(false)}))
	require.False(t, (&EnvironmentManagement{}).IsEqualTo(nil))
	require.Equal(t, []string{"management"}, (&EnvironmentManagement{}).Types())
	require.Contains(t, GetSupportedEnvironmentFeatureFlags(), "management")
}

func TestEnvironmentMarshalYAMLWithVariables(t *testing.T) {
	var configured Environment
	require.NoError(t, yaml.Unmarshal([]byte("type: ssh\naddress: target.example.org:22\nuser: alice\nacceptAllHostKeys: true\nvariables:\n  EDITOR: vim\n"), &configured))
	encoded, err := yaml.Marshal(&configured)
	require.NoError(t, err)
	var restored Environment
	require.NoError(t, yaml.Unmarshal(encoded, &restored))
	require.True(t, configured.IsEqualTo(restored))
}
