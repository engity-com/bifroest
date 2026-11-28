package session

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAssociationEligibilityRejectsOldRevisionBeforeResolvingItsTarget(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	request := associationRequestFor(t, "same-target")
	first, created, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.NoError(t, err)
	require.True(t, created)
	resolve := request.ResolveTarget
	var resolutions int
	request.ResolveTarget = func(ctx context.Context, ref Reference) (Target, error) {
		require.NotEqual(t, first.Id(), ref.Id, "a previous environment revision must not be evaluated using new target rules")
		resolutions++
		return resolve(ctx, ref)
	}
	request.Eligible = func(_ context.Context, candidate Session) (bool, error) {
		return candidate.Id() != first.Id(), nil
	}
	second, created, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, first.Id(), second.Id())
	require.Equal(t, 1, resolutions, "only the prospective new session needs a target resolution")
	stillPresent, err := repository.FindBy(t.Context(), first.Flow(), first.Id(), nil)
	require.NoError(t, err)
	require.Equal(t, first.Id(), stillPresent.Id(), "ineligibility must not delete the previous session")
}

func TestAssociationEligibilityErrorDoesNotResolveTargetOrCreateSession(t *testing.T) {
	repository, _ := newAssociationRepository(t)
	request := associationRequestFor(t, "same-target")
	_, _, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.NoError(t, err)
	rejected := errors.New("cannot inspect runtime ownership")
	request.Eligible = func(context.Context, Session) (bool, error) { return false, rejected }
	request.ResolveTarget = func(context.Context, Reference) (Target, error) {
		t.Error("a rejected candidate must not reach target resolution")
		return "", nil
	}
	found, created, err := repository.ResolveAssociatedSession(t.Context(), request)
	require.ErrorIs(t, err, rejected)
	require.Nil(t, found)
	require.False(t, created)
	var count int
	require.NoError(t, repository.FindAll(t.Context(), func(context.Context, Session) (bool, error) {
		count++
		return true, nil
	}, nil))
	require.Equal(t, 1, count)
}
