package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnvironmentManagementConfiguration(t *testing.T) {
	for _, test := range []struct {
		name                  string
		configuration         string
		includingCredentials  bool
		allowArtifactTransfer bool
	}{
		{"default redaction", "type: management\n", false, false},
		{"explicit credentials", "type: management\nincludingCredentials: true\n", true, false},
		{"artifact transfer", "type: management\nallowArtifactTransfer: true\n", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var configured Environment
			require.NoError(t, yaml.Unmarshal([]byte(test.configuration), &configured))
			management, ok := configured.V.(*EnvironmentManagement)
			require.True(t, ok)
			require.Equal(t, test.includingCredentials, management.IncludingCredentials)
			require.Equal(t, test.allowArtifactTransfer, management.AllowArtifactTransfer)
			encoded, err := yaml.Marshal(&configured)
			require.NoError(t, err)
			var restored Environment
			require.NoError(t, yaml.Unmarshal(encoded, &restored))
			require.True(t, configured.IsEqualTo(restored))
			require.Contains(t, management.FeatureFlags(), "management")
		})
	}
	var configured Environment
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nincludingCredentials: invalid\n"), &configured), "cannot unmarshal")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nincludingCredential: true\n"), &configured), "includingCredential")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nallowArtifactTransfer: invalid\n"), &configured), "cannot unmarshal")
	require.ErrorContains(t, yaml.Unmarshal([]byte("type: management\nvariables:\n  SECRET: value\n"), &configured), "not supported")
	require.False(t, (&EnvironmentManagement{}).IsEqualTo(EnvironmentManagement{IncludingCredentials: true}))
	require.False(t, (&EnvironmentManagement{}).IsEqualTo(EnvironmentManagement{AllowArtifactTransfer: true}))
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
