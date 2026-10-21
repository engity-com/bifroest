//go:build windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestLocalAuthenticationUsesResolvedAccount(t *testing.T) {
	identity, err := AuthenticationOf(&local{
		user:   windowslocal.Account{Name: "resolved-account", SID: "S-1-5-21-1-2-3-1001"},
		remote: authenticationTestRemote("requested-name"),
	})
	require.NoError(t, err)
	require.Equal(t, "resolved-account", identity.Principal)
	require.Equal(t, "S-1-5-21-1-2-3-1001", identity.Subject)
}
