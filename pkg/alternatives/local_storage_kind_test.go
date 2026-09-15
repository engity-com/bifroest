//go:build local_build && local_kind

package alternatives

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

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

func TestProbeLocalKindProviderRetriesPodmanOnce(t *testing.T) {
	var calls [][]string
	actual := probeLocalKindProvider(context.Background(), "podman", func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if len(calls) == 1 {
			return stderrors.New("first start failed")
		}
		return nil
	})

	assert.True(t, actual)
	assert.Equal(t, [][]string{
		{"podman", "ps", "--all", "--quiet"},
		{"podman", "ps", "--all", "--quiet"},
	}, calls)
}

func TestProbeLocalKindProviderDoesNotRetryDocker(t *testing.T) {
	var calls int
	actual := probeLocalKindProvider(context.Background(), "docker", func(context.Context, string, ...string) error {
		calls++
		return stderrors.New("unavailable")
	})

	assert.False(t, actual)
	assert.Equal(t, 1, calls)
}

func TestProbeLocalKindProviderReservesDeadlineForRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var calls int
	actual := probeLocalKindProvider(ctx, "podman", func(ctx context.Context, _ string, _ ...string) error {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})

	assert.True(t, actual)
	assert.Equal(t, 2, calls)
}
