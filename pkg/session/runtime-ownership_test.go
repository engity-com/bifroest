package session

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func runtimeOwnershipTestDigests() map[configuration.FlowName]configuration.RuntimeFlowDigests {
	return map[configuration.FlowName]configuration.RuntimeFlowDigests{
		"work": {Environment: strings.Repeat("a", 64), Owner: strings.Repeat("b", 64)},
	}
}

func runtimeOwnershipTestState(t *testing.T) *RuntimeState {
	t.Helper()
	result, err := AdvanceRuntimeState(nil, runtimeOwnershipTestDigests())
	require.NoError(t, err)
	require.NoError(t, result.Validate())
	return result
}

func TestRuntimeOwnershipRevisionsKeepUnchangedButNeverReviveOldValues(t *testing.T) {
	digests := runtimeOwnershipTestDigests()
	first := runtimeOwnershipTestState(t)
	unchanged, err := AdvanceRuntimeState(first, digests)
	require.NoError(t, err)
	require.NotEqual(t, first.Revision, unchanged.Revision)
	require.Equal(t, first.Flows, unchanged.Flows)
	next := digests["work"]
	next.Environment, next.Owner = strings.Repeat("c", 64), strings.Repeat("d", 64)
	digests["work"] = next
	changed, err := AdvanceRuntimeState(unchanged, digests)
	require.NoError(t, err)
	require.Equal(t, first.Flows["work"].Incarnation, changed.Flows["work"].Incarnation)
	require.NotEqual(t, first.Flows["work"].Environment, changed.Flows["work"].Environment)
	require.NotEqual(t, first.Flows["work"].Owner, changed.Flows["work"].Owner)
	reverted, err := AdvanceRuntimeState(changed, runtimeOwnershipTestDigests())
	require.NoError(t, err)
	require.NotEqual(t, first.Flows["work"].Environment, reverted.Flows["work"].Environment)
	require.NotEqual(t, first.Flows["work"].Owner, reverted.Flows["work"].Owner)
	require.Equal(t, strings.Repeat("a", 64), first.Flows["work"].EnvironmentDigest, "preparation must not mutate its parent")
	removed, err := AdvanceRuntimeState(reverted, map[configuration.FlowName]configuration.RuntimeFlowDigests{})
	require.NoError(t, err)
	recreated, err := AdvanceRuntimeState(removed, runtimeOwnershipTestDigests())
	require.NoError(t, err)
	require.NotEqual(t, first.Flows["work"].Incarnation, recreated.Flows["work"].Incarnation)
}

func TestRuntimeOwnershipProviderChangeKeepsEnvironmentButNotOwner(t *testing.T) {
	first := runtimeOwnershipTestState(t)
	digests := runtimeOwnershipTestDigests()
	digests["work"] = configuration.RuntimeFlowDigests{Environment: digests["work"].Environment, Owner: strings.Repeat("c", 64)}
	next, err := AdvanceRuntimeState(first, digests)
	require.NoError(t, err)
	require.Equal(t, first.Flows["work"].Incarnation, next.Flows["work"].Incarnation)
	require.Equal(t, first.Flows["work"].Environment, next.Flows["work"].Environment)
	require.NotEqual(t, first.Flows["work"].Owner, next.Flows["work"].Owner)
}

func TestRuntimeOwnershipRejectsUnversionedAndMalformedIdentity(t *testing.T) {
	state := runtimeOwnershipTestState(t)
	flow := state.Flows["work"]
	owner := RuntimeOwnership{Schema: RuntimeOwnershipSchema, Flow: "work", SessionID: MustNewId(), Incarnation: flow.Incarnation, Environment: flow.Environment, Owner: flow.Owner}
	require.True(t, owner.Matches(flow))
	for _, alter := range []func(*RuntimeOwnership){
		func(value *RuntimeOwnership) { value.Schema = "future-format" },
		func(value *RuntimeOwnership) { value.Flow = ".." },
		func(value *RuntimeOwnership) { value.SessionID = Id{} },
		func(value *RuntimeOwnership) { value.Environment = "" },
		func(value *RuntimeOwnership) { value.Owner = RuntimeRevision(strings.Repeat("0", 64)) },
		func(value *RuntimeOwnership) { value.Incarnation = RuntimeRevision(strings.Repeat("A", 64)) },
	} {
		bad := owner
		alter(&bad)
		require.ErrorIs(t, bad.Validate(), ErrInvalidRuntimeOwnership)
		require.False(t, bad.Matches(flow))
	}
	_, err := AdvanceRuntimeState(nil, nil)
	require.ErrorIs(t, err, ErrInvalidRuntimeState)
	bad := *state
	bad.Schema = "future-format"
	_, err = AdvanceRuntimeState(&bad, runtimeOwnershipTestDigests())
	require.ErrorIs(t, err, ErrInvalidRuntimeState)
}
