package session

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsActiveConnectionSurvivesConcurrentReplacement(t *testing.T) {
	repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	local := created.(*fs)
	for i := 0; i < 50; i++ {
		previous, err := local.ConnectionInterceptor(t.Context())
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() { done <- previous.Close() }()
		current, err := local.ConnectionInterceptor(t.Context())
		require.NoError(t, err)
		require.NoError(t, <-done)
		require.True(t, local.HasActiveConnections())
		require.NoError(t, current.Close())
		require.False(t, local.HasActiveConnections())
	}
}

func TestFsDisposedSessionCannotAcceptNewConnection(t *testing.T) {
	repository, err := NewFsRepository(t.Context(), newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	created, err := repository.Create(t.Context(), "test", fsRepositoryTestRemote{}, []byte("authorization"))
	require.NoError(t, err)
	_, err = created.Dispose(t.Context())
	require.NoError(t, err)
	_, err = created.ConnectionInterceptor(t.Context())
	require.ErrorContains(t, err, "disposed session")
}
