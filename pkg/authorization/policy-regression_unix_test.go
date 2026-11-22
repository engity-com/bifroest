//go:build unix

package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type characterizationManagedContext struct {
	managed, available bool
	err                error
}

func (characterizationManagedContext) Context() context.Context { return nil }
func (this characterizationManagedContext) ResolveLocalUserManaged(configuration.FlowName, *user.User) (bool, bool, error) {
	return this.managed, this.available, this.err
}

func TestPolicyRegressionUnixLocalIdentityAndManagementView(t *testing.T) {
	for _, uid := range []user.Id{0, 1234, ^user.Id(0)} {
		account := &user.User{Name: "canonical", Uid: uid, Group: user.Group{Name: "primary", Gid: 7}, Groups: user.Groups{{Name: "second", Gid: 9}}, HomeDir: "/fixture", Shell: "/bin/sh"}
		auth := &local{user: account, flow: "flow", remote: authenticationTestRemote("requested")}
		identity, err := auth.Authentication()
		require.NoError(t, err)
		require.Equal(t, authentication.Identity{Principal: "canonical", Issuer: "local", Subject: uid.String()}, identity)
		for _, scenario := range []characterizationManagedContext{{managed: true, available: true}, {available: true}, {}} {
			value, present, err := auth.GetField("user", scenario)
			require.NoError(t, err)
			require.True(t, present)
			view := value.(interface {
				GetField(string) (any, bool, error)
			})
			managed, present, err := view.GetField("managed")
			require.NoError(t, err)
			require.True(t, present)
			if scenario.available {
				require.Equal(t, scenario.managed, managed)
			} else {
				require.Nil(t, managed)
			}
			for _, field := range []string{"name", "uid", "group", "groups", "homeDir", "shell"} {
				want, found, err := account.GetField(field)
				require.NoError(t, err)
				got, gotFound, err := view.GetField(field)
				require.NoError(t, err)
				require.Equal(t, found, gotFound)
				require.Equal(t, want, got)
			}
		}
		upstream := berrors.Network.Newf("group lookup failed")
		_, _, err = auth.GetField("user", characterizationManagedContext{err: upstream})
		require.ErrorIs(t, err, upstream)
		require.True(t, berrors.Network.IsErr(err))
		req := &userEnabledRequest{Request: characterizationRequest{ctx: t.Context()}, user: account}
		got, err := template.MustNewString(`{{ .marker }}:{{ .user.name }}`).Render(req)
		require.NoError(t, err)
		require.Equal(t, "parent:canonical", got)
	}
	_, err := (&local{}).Authentication()
	require.ErrorIs(t, err, ErrAuthenticationUnavailable)
}
