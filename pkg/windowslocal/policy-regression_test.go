package windowslocal

import (
	"testing"

	"github.com/stretchr/testify/require"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

func TestPolicyRegressionObservedPasswordAccountFields(t *testing.T) {
	for _, groups := range [][]group{nil, {}, {{Name: "second", SID: "S-1-5-32-546"}, {Name: "first", SID: "S-1-5-32-545"}}} {
		view := &PasswordAccount{account: Account{Name: "fixture", SID: "S-1-5-21-1-2-3-1001"}, displayName: "Display", homeDir: `C:\fixture`, shell: "shell", groups: groups}
		for field, want := range map[string]any{"name": "fixture", "uid": view.account.SID, "displayName": "Display", "homeDir": `C:\fixture`, "shell": "shell", "managed": nil} {
			value, present, err := view.GetField(field)
			require.NoError(t, err)
			require.True(t, present)
			require.Equal(t, want, value)
		}
		value, present, err := view.GetField("groups")
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, groups, value)
		if len(groups) > 0 {
			value.([]group)[0].Name = "caller mutation"
			require.Equal(t, "second", view.groups[0].Name)
		}
		value, _, err = view.GetField("gids")
		require.NoError(t, err)
		ids := make([]string, len(groups))
		for i, group := range groups {
			ids[i] = group.SID
		}
		require.Equal(t, ids, value)
	}
	_, present, err := (*PasswordAccount)(nil).GetField("name")
	require.ErrorIs(t, err, ErrPasswordAccountPolicyUnavailable)
	require.False(t, present)
}

func TestPolicyRegressionPasswordAccountUnknownFieldError(t *testing.T) {
	_, present, err := (&PasswordAccount{}).GetField("unknown")
	require.EqualError(t, err, `unknown user field "unknown"`)
	require.False(t, present)
	require.True(t, berrors.Config.IsErr(err))
}
