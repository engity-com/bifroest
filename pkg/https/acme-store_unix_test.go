//go:build unix

package https

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestACMEPrivateStatePermissionsAreValidatedNotRepaired(t *testing.T) {
	clock := newACMETestClock()
	ca := newACMETestCA(t, clock)
	_, source, manager := newACMETestSource(t, ca, "app.example.org")
	require.NoError(t, manager.Prepare(context.Background()))
	for _, path := range []string{source.store.base.Name(), source.store.path, filepath.Join(source.store.path, certificateStateName("app.example.org"))} {
		original, err := os.Stat(path)
		require.NoError(t, err)
		require.NoError(t, os.Chmod(path, 0755))
		_, err = source.Certificate(context.Background(), "app.example.org", nil)
		require.Error(t, err)
		after, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0755), after.Mode().Perm())
		require.NoError(t, os.Chmod(path, original.Mode().Perm()))
	}
}
