//go:build unix

package user

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func snapshotTestText(value string) *string { return &value }

func snapshotTestFacts() AccountFacts {
	uid := Id(1234)
	groups := Groups{{Name: "second", Gid: 3000}, {Name: "first", Gid: 2000}}
	return AccountFacts{
		Name: "synthetic", Uid: &uid, DisplayName: snapshotTestText("Synthetic User"),
		Group: &Group{Name: "primary", Gid: 1000}, Groups: &groups,
		Shell: snapshotTestText("/bin/sh"), HomeDir: snapshotTestText("/fixture/home"),
	}
}

func TestSnapshotRetainsProductionUnixFieldsAndTypes(t *testing.T) {
	facts := snapshotTestFacts()
	view, err := NewSnapshot(facts)
	require.NoError(t, err)
	production := User{Name: facts.Name, Uid: *facts.Uid, DisplayName: *facts.DisplayName, Group: *facts.Group, Groups: *facts.Groups, Shell: *facts.Shell, HomeDir: *facts.HomeDir}
	for _, name := range []string{"name", "uid", "displayName", "group", "gid", "groups", "gids", "shell", "homeDir", "managed"} {
		expected, present, err := production.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		actual, present, err := view.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expected, actual, "field %s must retain its production value and type", name)
	}
	_, _, expected := production.GetField("unsupported")
	_, _, actual := view.GetField("unsupported")
	require.EqualError(t, actual, expected.Error())
	require.True(t, errors.Config.IsErr(actual))
	name, uid := view.Identity()
	require.Equal(t, "synthetic", name)
	require.Equal(t, Id(1234), uid)
}

func TestSnapshotCopiesInputsAndMutableResults(t *testing.T) {
	facts := snapshotTestFacts()
	view, err := NewSnapshot(facts)
	require.NoError(t, err)
	*facts.Uid = 5678
	*facts.DisplayName, *facts.Shell, *facts.HomeDir = "mutation", "mutation", "mutation"
	facts.Group.Name = "mutation"
	(*facts.Groups)[0].Name = "mutation"
	for range 3 {
		groups, _, err := view.GetField("groups")
		require.NoError(t, err)
		groups.(Groups)[0].Name = "reader mutation"
		ids, _, err := view.GetField("gids")
		require.NoError(t, err)
		ids.([]GroupId)[0] = 0
	}
	for name, expected := range map[string]any{
		"uid": Id(1234), "displayName": "Synthetic User", "shell": "/bin/sh", "homeDir": "/fixture/home",
		"group": Group{Name: "primary", Gid: 1000}, "gids": []GroupId{3000, 2000},
	} {
		actual, _, err := view.GetField(name)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	for range 4 {
		t.Run("parallel reader", func(t *testing.T) {
			t.Parallel()
			groups, _, err := view.GetField("groups")
			require.NoError(t, err)
			groups.(Groups)[0].Name = "reader mutation"
			ids, _, err := view.GetField("gids")
			require.NoError(t, err)
			require.Equal(t, []GroupId{3000, 2000}, ids)
		})
	}
}

func TestSnapshotDistinguishesMissingFieldsFromExplicitZeroAndEmptyValues(t *testing.T) {
	uid := Id(0)
	facts := AccountFacts{Name: "explicit-zero", Uid: &uid}
	view, err := NewSnapshot(facts)
	require.NoError(t, err)
	value, present, err := view.GetField("uid")
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, Id(0), value)
	for _, name := range []string{"group", "gid", "groups", "gids", "displayName", "shell", "homeDir"} {
		value, present, err := view.GetField(name)
		require.ErrorIs(t, err, ErrAccountFieldUnavailable)
		require.True(t, errors.Config.IsErr(err))
		require.False(t, present)
		require.Nil(t, value)
	}
	groups := Groups{}
	facts.Groups, facts.Group = &groups, &Group{Name: "explicit-zero-group", Gid: 0}
	facts.DisplayName, facts.Shell, facts.HomeDir = snapshotTestText(""), snapshotTestText(""), snapshotTestText("")
	view, err = NewSnapshot(facts)
	require.NoError(t, err)
	for name, expected := range map[string]any{"gid": GroupId(0), "groups": Groups{}, "gids": []GroupId{}, "displayName": "", "shell": "", "homeDir": "", "managed": nil} {
		actual, present, err := view.GetField(name)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expected, actual)
	}
	groups = nil
	view, err = NewSnapshot(facts)
	require.NoError(t, err)
	value, _, err = view.GetField("groups")
	require.NoError(t, err)
	require.Equal(t, Groups(nil), value)
}

func TestSnapshotRejectsMissingOrAmbiguousIdentities(t *testing.T) {
	for _, change := range []func(*AccountFacts){
		func(f *AccountFacts) { f.Uid = nil },
		func(f *AccountFacts) { f.Name = "" },
		func(f *AccountFacts) { f.Name = "sensitive\nidentity" },
		func(f *AccountFacts) { f.Group.Name = "" },
		func(f *AccountFacts) { (*f.Groups)[0].Name = "" },
		func(f *AccountFacts) { (*f.Groups)[0].Name = (*f.Groups)[1].Name },
		func(f *AccountFacts) { (*f.Groups)[0].Gid = (*f.Groups)[1].Gid },
	} {
		facts := snapshotTestFacts()
		change(&facts)
		view, err := NewSnapshot(facts)
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.NotContains(t, err.Error(), "sensitive")
		require.Nil(t, view)
	}
	for _, view := range []*Snapshot{nil, {}} {
		_, present, err := view.GetField("name")
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
		require.True(t, errors.Config.IsErr(err))
		require.False(t, present)
	}
}
