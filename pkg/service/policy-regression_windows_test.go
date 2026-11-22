//go:build windows

package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestPolicyRegressionWindowsManagementGuardsBeforeNativeAccess(t *testing.T) {
	ctx := newPrincipalTestContext("")
	account := windowslocal.Account{Name: "fixture", SID: "S-1-5-21-1-2-3-1001"}
	for _, environment := range []configuration.Environment{{}, {V: &configuration.EnvironmentSsh{}}, {V: &configuration.EnvironmentLocal{}}} {
		ctx.service.Configuration.Flows[0].Environment = environment
		managed, available, err := ctx.ResolveLocalWindowsUserManaged("flow", account)
		require.NoError(t, err)
		require.False(t, managed)
		require.False(t, available)
	}
	ctx.service.Configuration.Flows[0].Environment.V = (*configuration.EnvironmentLocal)(nil)
	managed, available, err := ctx.ResolveLocalWindowsUserManaged("flow", account)
	require.NoError(t, err)
	require.False(t, managed)
	require.False(t, available)
}
