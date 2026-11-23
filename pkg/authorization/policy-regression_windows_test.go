//go:build windows

package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type characterizationWindowsManagedContext struct{ managed, available bool }

func (characterizationWindowsManagedContext) Context() context.Context { return nil }
func (this characterizationWindowsManagedContext) ResolveLocalWindowsUserManaged(configuration.FlowName, windowslocal.Account) (bool, bool, error) {
	return this.managed, this.available, nil
}

type characterizationPasswordView struct{ account windowslocal.Account }

func (this characterizationPasswordView) Account() windowslocal.Account              { return this.account }
func (characterizationPasswordView) IsEqualTo(windowslocal.PasswordAccountView) bool { return false }
func (this characterizationPasswordView) GetField(name string) (any, bool, error) {
	if name == "homeDir" {
		return `C:\observed`, true, nil
	}
	return this.account.Name, true, nil
}

func TestPolicyRegressionWindowsLocalIdentityAndManagement(t *testing.T) {
	account := windowslocal.Account{Name: "canonical", SID: "S-1-5-21-1-2-3-1001"}
	auth := &local{user: account, flow: "flow", remote: authenticationTestRemote("requested")}
	identity, err := auth.Authentication()
	require.NoError(t, err)
	require.Equal(t, authentication.Identity{Principal: "canonical", Issuer: "local", Subject: account.SID}, identity)
	for _, scenario := range []characterizationWindowsManagedContext{{managed: true, available: true}, {available: true}, {}} {
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
		name, _, err := view.GetField("name")
		require.NoError(t, err)
		require.Equal(t, "canonical", name)
	}
	auth.passwordAccount = characterizationPasswordView{account: account}
	value, _, err := auth.GetField("user", characterizationWindowsManagedContext{})
	require.NoError(t, err)
	home, _, err := value.(interface {
		GetField(string) (any, bool, error)
	}).GetField("homeDir")
	require.NoError(t, err)
	require.Equal(t, `C:\observed`, home)
	request := &localUserRequest{Request: characterizationRequest{ctx: t.Context()}, user: account}
	value, _, err = request.GetField("user")
	require.NoError(t, err)
	require.Equal(t, account, value)
}
