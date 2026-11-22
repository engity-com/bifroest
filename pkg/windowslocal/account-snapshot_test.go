package windowslocal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func accountSnapshotTestText(value string) *string { return &value }

func accountSnapshotTestFacts() AccountFacts {
	groups := []AccountGroupFacts{{Name: "second", SID: "S-1-5-32-546"}, {Name: "first", SID: "S-1-5-32-545"}}
	return AccountFacts{
		Identity:    Account{Name: "alice", SID: "S-1-5-21-1-2-3-1001"},
		DisplayName: accountSnapshotTestText("Current Alice"), HomeDir: accountSnapshotTestText(`C:\Users\alice`),
		Shell: accountSnapshotTestText(`C:\Windows\system32\cmd.exe`), Groups: &groups,
	}
}

func TestAccountSnapshotUsesTheProductionPasswordAccountFieldMapping(t *testing.T) {
	m := newSAMPasswordViewModel(t)
	m.groups = []group{{Name: "second", SID: "S-1-5-32-546"}, {Name: "first", SID: "S-1-5-32-545"}}
	observed, err := readSAMPasswordAccount(m.ctx, m.account, m.operations())
	require.NoError(t, err)
	supplied, err := NewAccountSnapshot(accountSnapshotTestFacts())
	require.NoError(t, err)
	for _, name := range []string{"name", "uid", "displayName", "homeDir", "shell", "groups", "gids", "managed"} {
		expected, present, err := observed.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		actual, present, err := supplied.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expected, actual, "field %s must retain the production value and type", name)
	}
	name, sid := supplied.Identity()
	require.Equal(t, observed.Account().Name, name)
	require.Equal(t, observed.Account().SID, sid)
	_, isPolicyEvidence := any(supplied).(PasswordAccountView)
	require.False(t, isPolicyEvidence, "supplied facts must not stand in for a fresh native policy check")
	_, _, expected := observed.GetField("unknown")
	_, _, actual := supplied.GetField("unknown")
	require.EqualError(t, actual, expected.Error())
	require.True(t, errors.Config.IsErr(actual))
}

func TestAccountSnapshotIsImmutableAndPreservesGroupOrder(t *testing.T) {
	facts := accountSnapshotTestFacts()
	view, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	*facts.HomeDir = "caller mutation"
	*facts.Shell = "caller mutation"
	*facts.DisplayName = "caller mutation"
	facts.Identity.Name = "caller mutation"
	(*facts.Groups)[0].Name = "caller mutation"
	for range 3 {
		value, _, err := view.GetField("groups")
		require.NoError(t, err)
		value.([]group)[0].Name = "reader mutation"
		ids, _, err := view.GetField("gids")
		require.NoError(t, err)
		ids.([]string)[0] = "reader mutation"
	}
	for name, expected := range map[string]any{
		"name": "alice", "displayName": "Current Alice", "homeDir": `C:\Users\alice`,
		"shell": `C:\Windows\system32\cmd.exe`, "gids": []string{"S-1-5-32-546", "S-1-5-32-545"},
		"groups": []group{{Name: "second", SID: "S-1-5-32-546"}, {Name: "first", SID: "S-1-5-32-545"}},
	} {
		actual, present, err := view.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expected, actual)
	}
	for range 4 {
		t.Run("parallel reader", func(t *testing.T) {
			t.Parallel()
			value, _, err := view.GetField("groups")
			require.NoError(t, err)
			value.([]group)[0].Name = "independent reader"
			actual, _, err := view.GetField("gids")
			require.NoError(t, err)
			require.Equal(t, []string{"S-1-5-32-546", "S-1-5-32-545"}, actual)
		})
	}
}

func TestAccountSnapshotDistinguishesMissingEmptyAndNilMetadata(t *testing.T) {
	t.Setenv("COMSPEC", "must-not-be-used-as-a-shell-default")
	facts := AccountFacts{Identity: Account{Name: "synthetic", SID: "S-1-5-21-1-2-3-1001"}}
	view, err := NewAccountSnapshot(facts)
	require.NoError(t, err)
	for _, name := range []string{"shell", "homeDir", "displayName", "groups", "gids"} {
		value, present, err := view.GetField(name)
		require.ErrorIs(t, err, ErrAccountFieldUnavailable)
		require.True(t, errors.Config.IsErr(err))
		require.False(t, present)
		require.Nil(t, value)
	}
	value, present, err := view.GetField("managed")
	require.NoError(t, err)
	require.True(t, present)
	require.Nil(t, value, "account facts must not invent a flow's managed status")
	facts.Shell, facts.HomeDir, facts.DisplayName = accountSnapshotTestText(""), accountSnapshotTestText(""), accountSnapshotTestText("")
	groups := []AccountGroupFacts{}
	facts.Groups = &groups
	view, err = NewAccountSnapshot(facts)
	require.NoError(t, err)
	for _, name := range []string{"shell", "homeDir", "displayName"} {
		value, present, err := view.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, "", value)
	}
	value, _, err = view.GetField("groups")
	require.NoError(t, err)
	require.Equal(t, []group{}, value)
	groups = nil
	view, err = NewAccountSnapshot(facts)
	require.NoError(t, err)
	value, _, err = view.GetField("groups")
	require.NoError(t, err)
	require.Equal(t, []group(nil), value)
	value, _, err = view.GetField("gids")
	require.NoError(t, err)
	require.Equal(t, []string{}, value)
}

func TestAccountSnapshotRejectsIncompleteOrAmbiguousIdentities(t *testing.T) {
	for _, change := range []func(*AccountFacts){
		func(f *AccountFacts) { f.Identity.Name = "" },
		func(f *AccountFacts) { f.Identity.SID = "" },
		func(f *AccountFacts) { f.Identity.Name = "sensitive\nidentity" },
		func(f *AccountFacts) { f.Identity.SID = "\xff" },
		func(f *AccountFacts) { (*f.Groups)[0].Name = "" },
		func(f *AccountFacts) { (*f.Groups)[0].SID = "" },
		func(f *AccountFacts) { (*f.Groups)[0].Name = "FIRST" },
		func(f *AccountFacts) { (*f.Groups)[0].SID = (*f.Groups)[1].SID },
	} {
		facts := accountSnapshotTestFacts()
		change(&facts)
		view, err := NewAccountSnapshot(facts)
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.NotContains(t, err.Error(), "sensitive")
		require.Nil(t, view)
	}
	for _, view := range []*AccountSnapshot{nil, {}} {
		_, present, err := view.GetField("name")
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.False(t, present)
	}
}
