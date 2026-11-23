//go:build unix

package user

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestGroupNameMembershipSharesProductionAndSnapshotSemantics(t *testing.T) {
	for _, test := range []struct {
		label   string
		primary Group
		groups  Groups
		member  bool
	}{
		{"primary", Group{Name: "managed", Gid: 1}, nil, true},
		{"supplementary", Group{Name: "users", Gid: 1}, Groups{{Name: "other", Gid: 2}, {Name: "managed", Gid: 3}}, true},
		{"different GID", Group{Name: "managed", Gid: 99}, Groups{}, true},
		{"same GID is not membership", Group{Name: "other", Gid: 1}, Groups{{Name: "other-too", Gid: 1}}, false},
		{"case sensitive", Group{Name: "Managed"}, Groups{{Name: "MANAGED", Gid: 1}}, false},
		{"known empty list", Group{Name: "users"}, Groups{}, false},
		{"known nil list", Group{Name: "users"}, nil, false},
	} {
		t.Run(test.label, func(t *testing.T) {
			uid := Id(0)
			snapshot, err := NewSnapshot(AccountFacts{Name: "fixture", Uid: &uid, Group: &test.primary, Groups: &test.groups})
			require.NoError(t, err)
			for _, account := range []GroupFieldView{&User{Group: test.primary, Groups: test.groups}, snapshot} {
				member, err := IsInGroupByName(account, "managed")
				require.NoError(t, err)
				require.Equal(t, test.member, member)
			}
		})
	}
}

type groupMembershipTestView struct {
	get func(string) (any, bool, error)
}

func (this groupMembershipTestView) GetField(name string) (any, bool, error) { return this.get(name) }

func TestGroupNameMembershipRequiresOnlyReachedFacts(t *testing.T) {
	uid := Id(0)
	for _, test := range []struct {
		label   string
		primary *Group
		groups  *Groups
		member  bool
		err     error
	}{
		{"missing primary", nil, nil, false, ErrAccountFieldUnavailable},
		{"missing primary is not supplied by supplementary", nil, &Groups{{Name: "managed"}}, false, ErrAccountFieldUnavailable},
		{"primary match does not require supplementary", &Group{Name: "managed"}, nil, true, nil},
		{"missing supplementary after primary mismatch", &Group{Name: "users"}, nil, false, ErrAccountFieldUnavailable},
	} {
		t.Run(test.label, func(t *testing.T) {
			account, err := NewSnapshot(AccountFacts{Name: "fixture", Uid: &uid, Group: test.primary, Groups: test.groups})
			require.NoError(t, err)
			member, err := IsInGroupByName(account, "managed")
			if test.err != nil {
				require.ErrorIs(t, err, test.err)
				require.True(t, errors.Config.IsErr(err))
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.member, member)
		})
	}
	calls := 0
	member, err := IsInGroupByName(groupMembershipTestView{get: func(name string) (any, bool, error) {
		calls++
		require.Equal(t, "group", name)
		return Group{Name: "managed"}, true, nil
	}}, "managed")
	require.NoError(t, err)
	require.True(t, member)
	require.Equal(t, 1, calls)
}

func TestGroupNameMembershipRejectsUnavailableOrWrongFieldTypes(t *testing.T) {
	for _, account := range []GroupFieldView{nil, (*User)(nil), (*Snapshot)(nil)} {
		_, err := IsInGroupByName(account, "managed")
		require.ErrorIs(t, err, ErrInvalidAccountFacts)
	}
	for _, test := range []struct {
		primary, groups any
		present         bool
		err             error
	}{
		{nil, nil, false, ErrAccountFieldUnavailable},
		{nil, nil, true, ErrInvalidAccountFacts},
		{"managed", nil, true, ErrInvalidAccountFacts},
		{Group{Name: "users"}, []string{"managed"}, true, ErrInvalidAccountFacts},
	} {
		view := groupMembershipTestView{get: func(name string) (any, bool, error) {
			if name == "group" {
				return test.primary, test.present, nil
			}
			return test.groups, test.present, nil
		}}
		_, err := IsInGroupByName(view, "managed")
		require.ErrorIs(t, err, test.err)
		require.True(t, errors.Config.IsErr(err))
	}
	upstream := errors.Network.Newf("explicit source failure")
	_, err := IsInGroupByName(groupMembershipTestView{get: func(string) (any, bool, error) { return nil, false, upstream }}, "managed")
	require.ErrorIs(t, err, upstream)
	require.True(t, errors.Network.IsErr(err))
	_, err = IsInGroupByName(groupMembershipTestView{get: func(name string) (any, bool, error) {
		if name == "group" {
			return Group{Name: "users"}, true, nil
		}
		return nil, false, nil
	}}, "managed")
	require.ErrorIs(t, err, ErrAccountFieldUnavailable)
}
