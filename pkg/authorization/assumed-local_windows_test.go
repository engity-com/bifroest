//go:build windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func TestAssumedLocalWindowsAuthenticationMatchesProductionIdentity(t *testing.T) {
	lookup, _ := assumedLocalWindowsTestLookup(t)
	bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), "canonical", lookup)
	require.NoError(t, err)
	actual, err := bound.Authentication()
	require.NoError(t, err)
	// Authentication() only maps these already supplied selectors. No native
	// account getter, credential validation, token or profile access is involved.
	expected, err := AuthenticationOf(&local{
		user:   windowslocal.Account{Name: "canonical", SID: "S-1-5-21-1-2-3-1001"},
		remote: authenticationTestRemote("different-requesting-name"),
	})
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
