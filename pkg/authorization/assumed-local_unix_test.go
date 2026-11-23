//go:build unix

package authorization

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestAssumedLocalUnixAuthenticationUsesProductionIdentityAndExplicitZeroUID(t *testing.T) {
	uid := user.Id(0)
	groups := user.Groups{}
	account, err := user.NewSnapshot(user.AccountFacts{Name: "fixture", Uid: &uid, Groups: &groups})
	require.NoError(t, err)
	lookup, err := user.NewMemoryLookup(user.AccountLookupFacts{Accounts: []*user.Snapshot{account}})
	require.NoError(t, err)
	bound, err := BindAssumedLocalUnixAuthentication(t.Context(), assumedLocalTestFlow(), "fixture", lookup)
	require.NoError(t, err)
	actual, err := bound.Authentication()
	require.NoError(t, err)
	expected, err := AuthenticationOf(&local{user: &user.User{Name: "fixture", Uid: 0}, remote: authenticationTestRemote("different-requesting-name")})
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, "0", actual.Subject)
	view, err := bound.Account()
	require.NoError(t, err)
	value, _, err := view.GetField("uid")
	require.NoError(t, err)
	require.Equal(t, user.Id(0), value)
	auth := assumedLocalBindingTestAuthorization{binding: bound}
	identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(`{{ if eq .authorization.user.uid 0 }}mapped-{{ .authentication.principal }}{{ end }}`), func(identity authentication.Identity) PrincipalMappingContext {
		return newPrincipalMappingTestContext(t, identity, auth)
	})
	require.NoError(t, err)
	require.Equal(t, "mapped-fixture", identity.Principal)
	require.Equal(t, actual.Subject, identity.Subject)
	require.Equal(t, actual.Issuer, identity.Issuer)
	*account = user.Snapshot{}
	*lookup = user.MemoryLookup{}
	_, err = bound.Authentication()
	require.NoError(t, err)
}

func TestAssumedLocalUnixAuthenticationPreservesMissingFactsAndRejectsWrongFlows(t *testing.T) {
	lookup, err := user.NewMemoryLookup(user.AccountLookupFacts{AbsentNames: []string{"absent"}})
	require.NoError(t, err)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"", ErrInvalidLocalAuthenticationAssumption}, {"absent", user.ErrNoSuchUser}, {"unknown", user.ErrAccountNotModeled},
	} {
		bound, err := BindAssumedLocalUnixAuthentication(t.Context(), assumedLocalTestFlow(), test.name, lookup)
		require.ErrorIs(t, err, test.err)
		require.Nil(t, bound)
	}
	bound, err := BindAssumedLocalUnixAuthentication(t.Context(), nil, "fixture", lookup)
	require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
	require.True(t, errors.Config.IsErr(err))
	require.Nil(t, bound)
	for _, source := range []*user.MemoryLookup{nil, {}} {
		_, err := BindAssumedLocalUnixAuthentication(t.Context(), assumedLocalTestFlow(), "fixture", source)
		require.ErrorIs(t, err, user.ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = BindAssumedLocalUnixAuthentication(canceled, assumedLocalTestFlow(), "fixture", lookup)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, errors.System.IsErr(err))
}
