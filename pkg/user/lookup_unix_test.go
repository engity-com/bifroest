//go:build unix

package user

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestMemoryLookupSeparatesExistingAbsentAndUnmodeledAccounts(t *testing.T) {
	facts := snapshotTestFacts()
	*facts.Uid = 0
	account, err := NewSnapshot(facts)
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*Snapshot{account}, AbsentNames: []string{"absent"}, AbsentIds: []Id{99}})
	require.NoError(t, err)
	for _, read := range []func() (*Snapshot, error){
		func() (*Snapshot, error) { return lookup.LookupByName(t.Context(), "synthetic") },
		func() (*Snapshot, error) { return lookup.LookupById(t.Context(), 0) },
	} {
		actual, err := read()
		require.NoError(t, err)
		name, uid := actual.Identity()
		require.Equal(t, "synthetic", name)
		require.Equal(t, Id(0), uid)
	}
	for _, test := range []struct {
		read func() (*Snapshot, error)
		err  error
	}{
		{func() (*Snapshot, error) { return lookup.LookupByName(t.Context(), "absent") }, ErrNoSuchUser},
		{func() (*Snapshot, error) { return lookup.LookupById(t.Context(), 99) }, ErrNoSuchUser},
		{func() (*Snapshot, error) { return lookup.LookupByName(t.Context(), "root") }, ErrAccountNotModeled},
		{func() (*Snapshot, error) { return lookup.LookupByName(t.Context(), "SYNTHETIC") }, ErrAccountNotModeled},
		{func() (*Snapshot, error) { return lookup.LookupById(t.Context(), 100) }, ErrAccountNotModeled},
	} {
		actual, err := test.read()
		require.ErrorIs(t, err, test.err)
		require.Nil(t, actual)
	}
	name, uid, err := lookup.LookupIdentityByName(t.Context(), "synthetic")
	require.NoError(t, err)
	require.Equal(t, "synthetic", name)
	require.Equal(t, Id(0), uid)
	name, uid, err = lookup.LookupIdentityById(t.Context(), 0)
	require.NoError(t, err)
	require.Equal(t, "synthetic", name)
	require.Equal(t, Id(0), uid)
	_, _, err = lookup.LookupIdentityByName(t.Context(), "absent")
	require.ErrorIs(t, err, ErrNoSuchUser)
	_, _, err = lookup.LookupIdentityById(t.Context(), 100)
	require.ErrorIs(t, err, ErrAccountNotModeled)
	_, writable := any(lookup).(Repository)
	require.False(t, writable)
}

func TestMemoryLookupOwnsSnapshotsAndSupportsIndependentReaders(t *testing.T) {
	account, err := NewSnapshot(snapshotTestFacts())
	require.NoError(t, err)
	lookup, err := NewMemoryLookup(AccountLookupFacts{Accounts: []*Snapshot{account}})
	require.NoError(t, err)
	*account = Snapshot{}
	for i := range 8 {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()
			first, err := lookup.LookupByName(t.Context(), "synthetic")
			require.NoError(t, err)
			groups, _, err := first.GetField("groups")
			require.NoError(t, err)
			groups.(Groups)[0].Name = "reader mutation"
			*first = Snapshot{}
			second, err := lookup.LookupById(t.Context(), 1234)
			require.NoError(t, err)
			ids, _, err := second.GetField("gids")
			require.NoError(t, err)
			require.Equal(t, []GroupId{3000, 2000}, ids)
		})
	}
}

func TestMemoryLookupRejectsAmbiguousFactsAndUnavailableContexts(t *testing.T) {
	facts := snapshotTestFacts()
	account, err := NewSnapshot(facts)
	require.NoError(t, err)
	otherId := Id(5678)
	sameName, err := NewSnapshot(AccountFacts{Name: facts.Name, Uid: &otherId})
	require.NoError(t, err)
	sameId, err := NewSnapshot(AccountFacts{Name: "other", Uid: facts.Uid})
	require.NoError(t, err)
	for _, facts := range []AccountLookupFacts{
		{Accounts: []*Snapshot{nil}}, {Accounts: []*Snapshot{{}}},
		{Accounts: []*Snapshot{account, account}}, {Accounts: []*Snapshot{account, sameName}}, {Accounts: []*Snapshot{account, sameId}},
		{Accounts: []*Snapshot{account}, AbsentNames: []string{"synthetic"}}, {Accounts: []*Snapshot{account}, AbsentIds: []Id{1234}},
		{AbsentNames: []string{"absent", "absent"}}, {AbsentIds: []Id{0, 0}}, {AbsentNames: []string{""}},
	} {
		lookup, err := NewMemoryLookup(facts)
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.Nil(t, lookup)
	}
	lookup, err := NewMemoryLookup(AccountLookupFacts{})
	require.NoError(t, err)
	_, err = lookup.LookupById(t.Context(), 0)
	require.ErrorIs(t, err, ErrAccountNotModeled, "an empty inventory is not a universal not-found response")
	require.True(t, errors.Config.IsErr(err))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = lookup.LookupByName(canceled, "unknown")
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, errors.System.IsErr(err))
	_, err = lookup.LookupById(canceled, 0)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, errors.System.IsErr(err))
	_, err = lookup.LookupByName(nil, "unknown")
	require.ErrorIs(t, err, ErrAccountLookupUnavailable)
	require.True(t, errors.System.IsErr(err))
	for _, absent := range []*MemoryLookup{nil, {}} {
		_, err = absent.LookupByName(t.Context(), "unknown")
		require.ErrorIs(t, err, ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
		_, err = absent.LookupById(t.Context(), 0)
		require.ErrorIs(t, err, ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
	}
}

var _ IdentityLookup = (*MemoryLookup)(nil)
