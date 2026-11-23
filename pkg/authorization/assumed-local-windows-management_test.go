//go:build unix || windows

package authorization

import (
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/windowslocal"
	"github.com/stretchr/testify/require"
)

func TestAssumedWindowsManagementIsExplicitDirectSIDMembership(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	snapshot, err := windowslocal.NewAccountSnapshot(windowslocal.AccountFacts{Identity: windowslocal.Account{Name: "alice", SID: sid}})
	require.NoError(t, err)
	accounts, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{Accounts: []*windowslocal.AccountSnapshot{snapshot}})
	require.NoError(t, err)
	flow := assumedLocalTestFlow()
	flow.Environment.V = &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "managed"}}
	bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), flow, "ALICE", accounts)
	require.NoError(t, err)
	for _, test := range []struct {
		name    string
		members []string
		want    bool
	}{{"direct SID", []string{sid}, true}, {"other SID", []string{"S-1-5-21-1-2-3-1002"}, false}, {"explicit empty", []string{}, false}} {
		t.Run(test.name, func(t *testing.T) {
			groups, err := windowslocal.NewMemoryGroupLookup(windowslocal.GroupLookupFacts{Groups: []windowslocal.LocalGroupFacts{{Name: "managed", SID: "S-1-5-21-1-2-3-2001", Members: &test.members}}})
			require.NoError(t, err)
			view, err := bound.WindowsAccountWithManagement(t.Context(), flow, groups)
			require.NoError(t, err)
			value, present, err := view.GetField("managed")
			require.NoError(t, err)
			require.True(t, present)
			require.Equal(t, test.want, value)
		})
	}
	unknown, err := windowslocal.NewMemoryGroupLookup(windowslocal.GroupLookupFacts{})
	require.NoError(t, err)
	_, err = bound.WindowsAccountWithManagement(t.Context(), flow, unknown)
	require.ErrorIs(t, err, windowslocal.ErrGroupNotModeled)
	nonlocal := *flow
	nonlocal.Environment.V = &configuration.EnvironmentSsh{}
	view, err := bound.WindowsAccountWithManagement(t.Context(), &nonlocal, nil)
	require.NoError(t, err)
	value, present, err := view.GetField("managed")
	require.NoError(t, err)
	require.True(t, present)
	require.Nil(t, value)
	_, _, err = view.GetField("groups")
	require.ErrorIs(t, err, windowslocal.ErrAccountFieldUnavailable)
	wrong := *flow
	wrong.Name = "wrong"
	_, err = bound.WindowsAccountWithManagement(t.Context(), &wrong, unknown)
	require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
}
