package windowslocal

import (
	"context"
	"slices"
	"testing"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestControlledDirectMembershipUsesSIDAndOwnedObservations(t *testing.T) {
	const accountSID = "S-1-5-21-1-2-3-1001"
	members := []string{accountSID}
	lookup, err := NewMemoryGroupLookup(GroupLookupFacts{Groups: []LocalGroupFacts{{Name: "managed", SID: "S-1-5-21-1-2-3-2001", Members: &members}}, AbsentNames: []string{"absent"}})
	require.NoError(t, err)
	members[0] = "changed"
	for _, name := range []string{"managed", "MANAGED"} {
		member, err := lookup.IsMember(t.Context(), name, accountSID)
		require.NoError(t, err)
		require.True(t, member)
		member, err = lookup.IsMember(t.Context(), name, "S-1-5-21-1-2-3-1002")
		require.NoError(t, err)
		require.False(t, member)
	}
	member, err := lookup.IsMember(t.Context(), "absent", accountSID)
	require.NoError(t, err)
	require.False(t, member)
	_, err = lookup.IsMember(t.Context(), "unknown", accountSID)
	require.ErrorIs(t, err, ErrGroupNotModeled)
	require.True(t, errors.Config.IsErr(err))
	require.False(t, HasAccountSID(accountSID, slices.Values([]string{"alice", "S-1-5-21-1-2-3-1002"})))
}

func TestControlledMembershipDistinguishesUnknownEmptyAndCanceled(t *testing.T) {
	empty := []string{}
	lookup, err := NewMemoryGroupLookup(GroupLookupFacts{Groups: []LocalGroupFacts{
		{Name: "unknown", SID: "group-1"}, {Name: "empty", SID: "group-2", Members: &empty},
	}})
	require.NoError(t, err)
	_, err = lookup.IsMember(t.Context(), "unknown", "account")
	require.ErrorIs(t, err, ErrGroupNotModeled)
	member, err := lookup.IsMember(t.Context(), "empty", "account")
	require.NoError(t, err)
	require.False(t, member)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = lookup.IsMember(ctx, "empty", "account")
	require.ErrorIs(t, err, context.Canceled)
	_, err = lookup.IsMember(nil, "empty", "account")
	require.ErrorIs(t, err, ErrAccountLookupUnavailable)
	var missing *MemoryGroupLookup
	_, err = missing.IsMember(t.Context(), "empty", "account")
	require.ErrorIs(t, err, ErrAccountLookupUnavailable)
}

func TestControlledMembershipRejectsContradictoryFacts(t *testing.T) {
	duplicate := []string{"account", "account"}
	for _, facts := range []GroupLookupFacts{
		{Groups: []LocalGroupFacts{{Name: "group", SID: ""}}},
		{Groups: []LocalGroupFacts{{Name: "group", SID: "one"}, {Name: "GROUP", SID: "two"}}},
		{Groups: []LocalGroupFacts{{Name: "one", SID: "same"}, {Name: "two", SID: "same"}}},
		{Groups: []LocalGroupFacts{{Name: "group", SID: "one"}}, AbsentNames: []string{"GROUP"}},
		{Groups: []LocalGroupFacts{{Name: "group", SID: "one", Members: &duplicate}}},
		{AbsentNames: []string{"group", "GROUP"}},
	} {
		_, err := NewMemoryGroupLookup(facts)
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
	}
}
