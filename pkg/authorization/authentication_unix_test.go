//go:build unix

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalAuthenticationUsesResolvedAccount(t *testing.T) {
	identity, err := AuthenticationOf(&local{
		user: &user.User{Name: "resolved-account", Uid: 1234}, remote: authenticationTestRemote("requested-name"),
	})
	require.NoError(t, err)
	require.Equal(t, "resolved-account", identity.Principal)
	require.Equal(t, "1234", identity.Subject)
	_, err = AuthenticationOf(&local{remote: authenticationTestRemote("requested-name")})
	require.ErrorIs(t, err, ErrAuthenticationUnavailable)
}
