package session

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFsSessionInfoConcurrentLastAccess(t *testing.T) {
	ctx := t.Context()
	repository, err := NewFsRepository(ctx, newFsRepositoryTestConfiguration(t))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	sess, err := repository.Create(ctx, "test", fsRepositoryTestRemote{}, nil)
	require.NoError(t, err)
	info, err := sess.Info(ctx)
	require.NoError(t, err)
	created, err := info.Created(ctx)
	require.NoError(t, err)
	createdAt := created.At()
	require.Equal(t, StateNew, info.State())

	// Real access notifications update the same metadata exposed by a retained
	// Info/Created handle. Readers must not race with those in-memory writes.
	updated := make(chan error, 1)
	go func() {
		for range 64 {
			if _, err := sess.NotifyLastAccess(ctx, fsRepositoryTestRemote{}, StateAuthorized); err != nil {
				updated <- err
				return
			}
		}
		updated <- nil
	}()
	validStates, stableCreation := true, true
readLoop:
	for {
		state := info.State()
		validStates = validStates && (state == StateNew || state == StateAuthorized)
		stableCreation = stableCreation && created.At().Equal(createdAt)
		select {
		case err = <-updated:
			break readLoop
		default:
			runtime.Gosched()
		}
	}
	require.NoError(t, err)
	require.True(t, validStates, "readers must observe a valid session state")
	require.True(t, stableCreation, "last access must preserve the creation instant")
	require.Equal(t, StateAuthorized, info.State(), "retained metadata observes the state transition")

	restored, err := repository.FindBy(ctx, sess.Flow(), sess.Id(), nil)
	require.NoError(t, err)
	restoredInfo, err := restored.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, StateAuthorized, restoredInfo.State())
	restoredCreated, err := restoredInfo.Created(ctx)
	require.NoError(t, err)
	require.True(t, restoredCreated.At().Equal(createdAt))
}
