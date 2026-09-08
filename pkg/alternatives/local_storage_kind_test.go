//go:build local_build && local_kind

package alternatives

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectLocalKindCluster(t *testing.T) {
	tests := []struct {
		name      string
		clusters  []string
		requested string
		expected  string
		err       string
	}{
		{name: "none", err: "expected exactly one cluster, got 0"},
		{name: "one", clusters: []string{"bifroest"}, expected: "bifroest"},
		{name: "multiple", clusters: []string{"first", "second"}, err: "expected exactly one cluster, got 2"},
		{name: "requested", clusters: []string{"first", "second"}, requested: "second", expected: "second"},
		{name: "requested missing", clusters: []string{"first", "second"}, requested: "third", err: `requested cluster "third" not found`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := selectLocalKindCluster(tt.clusters, tt.requested)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				assert.Empty(t, actual)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestNewLocalKindProviderRejectsUnknownProvider(t *testing.T) {
	t.Setenv("KIND_EXPERIMENTAL_PROVIDER", "unknown")

	actual, err := newLocalKindProvider()

	require.ErrorContains(t, err, `unsupported KIND_EXPERIMENTAL_PROVIDER value "unknown"`)
	assert.Nil(t, actual)
}

func TestNewLocalKindProviderRejectsNerdctlWithoutDockerApi(t *testing.T) {
	t.Setenv("KIND_EXPERIMENTAL_PROVIDER", "nerdctl")

	actual, err := newLocalKindProvider()

	require.ErrorContains(t, err, "requires a Docker-compatible Docker or Podman API")
	assert.Nil(t, actual)
}

func TestResolveLocalKindProviderDetectsOnlySupportedProviders(t *testing.T) {
	var checked []string
	actual, err := resolveLocalKindProvider("", func(candidate string) bool {
		checked = append(checked, candidate)
		return candidate == "podman"
	})

	require.NoError(t, err)
	assert.Equal(t, "podman", actual)
	assert.Equal(t, []string{"docker", "podman"}, checked)
}

func TestResolveLocalKindProviderRejectsMissingSupportedProvider(t *testing.T) {
	actual, err := resolveLocalKindProvider("", func(string) bool { return false })

	require.ErrorContains(t, err, "cannot detect an available Docker or Podman provider")
	assert.Empty(t, actual)
}
