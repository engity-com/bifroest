package windowslocal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestMemoryLookupSeparatesExistingAbsentAndUnmodeledAccounts(t *testing.T) {
	facts := accountSnapshotTestFacts()
	account, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*AccountSnapshot{account}, AbsentNames: []string{"absent"}, AbsentSIDs: []string{"S-1-5-21-1-2-3-999"}})
	require.NoError(t, err)
	for _, read := range []func() (*AccountSnapshot, error){
		func() (*AccountSnapshot, error) { return lookup.LookupByName(t.Context(), "ALICE") },
		func() (*AccountSnapshot, error) { return lookup.LookupBySID(t.Context(), facts.Identity.SID) },
	} {
		actual, err := read()
		require.NoError(t, err)
		name, sid := actual.Identity()
		require.Equal(t, "alice", name)
		require.Equal(t, facts.Identity.SID, sid)
	}
	for _, test := range []struct {
		read func() (*AccountSnapshot, error)
		err  error
	}{
		{func() (*AccountSnapshot, error) { return lookup.LookupByName(t.Context(), "ABSENT") }, ErrNotFound},
		{func() (*AccountSnapshot, error) { return lookup.LookupBySID(t.Context(), "S-1-5-21-1-2-3-999") }, ErrNotFound},
		{func() (*AccountSnapshot, error) { return lookup.LookupByName(t.Context(), "Administrator") }, ErrAccountNotModeled},
		{func() (*AccountSnapshot, error) { return lookup.LookupBySID(t.Context(), "S-1-5-18") }, ErrAccountNotModeled},
	} {
		actual, err := test.read()
		require.ErrorIs(t, err, test.err)
		require.Nil(t, actual)
	}
	name, sid, err := lookup.LookupIdentityByName(t.Context(), "ALICE")
	require.NoError(t, err)
	require.Equal(t, "alice", name)
	require.Equal(t, facts.Identity.SID, sid)
	name, sid, err = lookup.LookupIdentityBySID(t.Context(), facts.Identity.SID)
	require.NoError(t, err)
	require.Equal(t, "alice", name)
	require.Equal(t, facts.Identity.SID, sid)
	_, _, err = lookup.LookupIdentityByName(t.Context(), "ABSENT")
	require.ErrorIs(t, err, ErrNotFound)
	_, _, err = lookup.LookupIdentityBySID(t.Context(), "S-1-5-18")
	require.ErrorIs(t, err, ErrAccountNotModeled)
}

func TestMemoryLookupOwnsSnapshotsAndSupportsIndependentReaders(t *testing.T) {
	account, err := NewAccountSnapshot(accountSnapshotTestFacts())
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*AccountSnapshot{account}})
	require.NoError(t, err)
	*account = AccountSnapshot{}
	for i := range 8 {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()
			first, err := lookup.LookupByName(t.Context(), "ALICE")
			require.NoError(t, err)
			groups, _, err := first.GetField("groups")
			require.NoError(t, err)
			groups.([]group)[0].Name = "reader mutation"
			*first = AccountSnapshot{}
			second, err := lookup.LookupBySID(t.Context(), "S-1-5-21-1-2-3-1001")
			require.NoError(t, err)
			ids, _, err := second.GetField("gids")
			require.NoError(t, err)
			require.Equal(t, []string{"S-1-5-32-546", "S-1-5-32-545"}, ids)
		})
	}
}

func TestMemoryLookupRejectsAmbiguousFactsAndUnavailableContexts(t *testing.T) {
	facts := accountSnapshotTestFacts()
	account, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	sameName, err := NewAccountSnapshot(AccountFacts{Identity: Account{Name: "ALICE", SID: "S-1-5-21-1-2-3-5678"}})
	require.NoError(t, err)
	sameSID, err := NewAccountSnapshot(AccountFacts{Identity: Account{Name: "other", SID: facts.Identity.SID}})
	require.NoError(t, err)
	for _, facts := range []AccountLookupFacts{
		{Accounts: []*AccountSnapshot{nil}}, {Accounts: []*AccountSnapshot{{}}},
		{Accounts: []*AccountSnapshot{account, account}}, {Accounts: []*AccountSnapshot{account, sameName}}, {Accounts: []*AccountSnapshot{account, sameSID}},
		{Accounts: []*AccountSnapshot{account}, AbsentNames: []string{"ALICE"}}, {Accounts: []*AccountSnapshot{account}, AbsentSIDs: []string{"S-1-5-21-1-2-3-1001"}},
		{AbsentNames: []string{"absent", "ABSENT"}}, {AbsentSIDs: []string{"known", "known"}}, {AbsentNames: []string{""}}, {AbsentSIDs: []string{""}},
	} {
		lookup, err := NewMemoryLookup(facts)
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.Nil(t, lookup)
	}
	lookup, err := NewMemoryLookup(AccountLookupFacts{})
	require.NoError(t, err)
	_, err = lookup.LookupBySID(t.Context(), "S-1-5-18")
	require.ErrorIs(t, err, ErrAccountNotModeled, "an empty inventory is not a universal not-found response")
	require.True(t, errors.Config.IsErr(err))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = lookup.LookupByName(canceled, "unknown")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, errors.System.IsErr(err))
	_, err = lookup.LookupBySID(canceled, "unknown")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, errors.System.IsErr(err))
	_, err = lookup.LookupByName(nil, "unknown")
	require.ErrorIs(t, err, ErrAccountLookupUnavailable)
	require.True(t, errors.System.IsErr(err))
	for _, absent := range []*MemoryLookup{nil, {}} {
		_, err = absent.LookupByName(t.Context(), "unknown")
		require.ErrorIs(t, err, ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
		_, err = absent.LookupBySID(t.Context(), "unknown")
		require.ErrorIs(t, err, ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
	}
}

var _ IdentityLookup = (*MemoryLookup)(nil)
