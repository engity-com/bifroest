//go:build local_kind

package alternatives

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectLocalKindCluster(t *testing.T) {
	tests := []struct {
		name     string
		clusters []string
		expected string
		err      string
	}{
		{name: "none", err: "expected exactly one cluster, got 0"},
		{name: "one", clusters: []string{"bifroest"}, expected: "bifroest"},
		{name: "multiple", clusters: []string{"first", "second"}, err: "expected exactly one cluster, got 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := selectLocalKindCluster(tt.clusters)
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
