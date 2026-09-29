package session

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsCleanupTokenUpdateAfterDisposeIsCompareAndSwap(t *testing.T) {
	repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	original := []byte(`{"version":2,"user":{"name":"alice","uid":"1234","killProcessesOnDispose":true}}`)
	updated := []byte(`{"version":2,"user":{"name":"alice","uid":"1234","killProcessesOnDispose":true,"processesKilledOnDispose":true}}`)
	require.NoError(t, created.SetEnvironmentToken(t.Context(), original))
	_, err = created.Dispose(t.Context())
	require.NoError(t, err)
	require.Error(t, created.SetEnvironmentToken(t.Context(), updated))
	writer := created.(EnvironmentCleanupTokenUpdater)
	require.NoError(t, writer.UpdateEnvironmentTokenForCleanup(t.Context(), original, updated))
	actual, err := created.EnvironmentToken(t.Context())
	require.NoError(t, err)
	require.Equal(t, updated, actual)
	require.Error(t, writer.UpdateEnvironmentTokenForCleanup(t.Context(), original, updated))
	require.NoError(t, created.SetEnvironmentToken(t.Context(), nil))
	require.Error(t, writer.UpdateEnvironmentTokenForCleanup(t.Context(), updated, original))
}
