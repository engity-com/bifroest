package session

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestInspectFsSessionsWorksWhileWriterHoldsLock(t *testing.T) {
	conf := newFsRepositoryTestConfiguration(t)
	repository, err := NewFsRepository(t.Context(), conf)
	require.NoError(t, err)
	defer func() { require.NoError(t, repository.Close()) }()
	created, err := repository.Create(t.Context(), "admin", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	var ids []Id
	require.NoError(t, InspectFsSessions(t.Context(), conf, func(ctx context.Context, found Info) (bool, error) {
		ids = append(ids, found.Id())
		validUntil, err := found.ValidUntil(ctx)
		require.NoError(t, err)
		require.False(t, validUntil.IsZero())
		return true, nil
	}, nil))
	require.Equal(t, []Id{created.Id()}, ids)
	// Opening a second writer is still correctly rejected.
	_, err = NewFsRepository(t.Context(), conf)
	require.ErrorContains(t, err, "already locked")
}

func TestInspectFsSessionsDoesNotCreateMissingStorage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "sessions")
	require.NoError(t, InspectFsSessions(t.Context(), &configuration.SessionFs{Storage: missing}, func(context.Context, Info) (bool, error) {
		t.Fatal("unexpected session in missing storage")
		return false, nil
	}, nil))
	require.NoDirExists(t, missing)
	require.ErrorContains(t, InspectFsSessions(t.Context(), nil, func(context.Context, Info) (bool, error) { return true, nil }, nil), "requires an FS configuration")
}
