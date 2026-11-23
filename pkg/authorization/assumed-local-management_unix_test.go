//go:build unix

package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/user"
)

func assumedManagedUnixTestBinding(t *testing.T, primary *user.Group, groups *user.Groups) (*AssumedLocalAuthentication, *configuration.Flow) {
	t.Helper()
	uid := user.Id(0)
	account, err := user.NewSnapshot(user.AccountFacts{Name: "fixture", Uid: &uid, Group: primary, Groups: groups})
	require.NoError(t, err)
	lookup, err := user.NewMemoryLookup(user.AccountLookupFacts{Accounts: []*user.Snapshot{account}})
	require.NoError(t, err)
	flow := assumedLocalTestFlow()
	flow.Environment = configuration.Environment{V: &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{ManagedGroup: "managed"}}}
	bound, err := BindAssumedLocalUnixAuthentication(t.Context(), flow, "fixture", lookup)
	require.NoError(t, err)
	return bound, flow
}

func TestAssumedLocalUnixManagementUsesSharedMembershipAndPrincipalEvaluation(t *testing.T) {
	for _, test := range []struct {
		label   string
		primary *user.Group
		groups  *user.Groups
		managed bool
		err     error
	}{
		{"primary", &user.Group{Name: "managed"}, nil, true, nil},
		{"supplementary", &user.Group{Name: "users"}, &user.Groups{{Name: "managed"}}, true, nil},
		{"known unmanaged", &user.Group{Name: "users"}, &user.Groups{}, false, nil},
		{"known nil supplementary", &user.Group{Name: "users"}, new(user.Groups), false, nil},
		{"case sensitive", &user.Group{Name: "Managed"}, &user.Groups{}, false, nil},
		{"unknown primary", nil, &user.Groups{{Name: "managed"}}, false, user.ErrAccountFieldUnavailable},
		{"unknown supplementary", &user.Group{Name: "users"}, nil, false, user.ErrAccountFieldUnavailable},
	} {
		t.Run(test.label, func(t *testing.T) {
			bound, flow := assumedManagedUnixTestBinding(t, test.primary, test.groups)
			view, err := bound.UnixAccountWithManagement(t.Context(), flow)
			if test.err != nil {
				require.ErrorIs(t, err, test.err)
				require.True(t, errors.Config.IsErr(err))
				require.Nil(t, view)
				return
			}
			require.NoError(t, err)
			managed, present, err := view.GetField("managed")
			require.NoError(t, err)
			require.True(t, present)
			require.Equal(t, test.managed, managed)
			uid, _, err := view.GetField("uid")
			require.NoError(t, err)
			require.Equal(t, user.Id(0), uid)
			identity, err := bound.Authentication()
			require.NoError(t, err)
			auth := accountSnapshotTestAuthorization{identity: identity, account: view}
			mapped, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(`{{ if .authorization.user.managed }}managed{{ else }}unmanaged{{ end }}-{{ .authentication.principal }}`), func(identity authentication.Identity) PrincipalMappingContext {
				return newPrincipalMappingTestContext(t, identity, auth)
			})
			require.NoError(t, err)
			expected := "unmanaged-fixture"
			if test.managed {
				expected = "managed-fixture"
			}
			require.Equal(t, expected, mapped.Principal)
			require.Equal(t, identity.Issuer, mapped.Issuer)
			require.Equal(t, "0", mapped.Subject)
			original, err := bound.Account()
			require.NoError(t, err)
			_, _, err = original.GetField("managed")
			require.ErrorIs(t, err, ErrAssumedLocalFieldUnavailable, "resolving one view must not mutate the authentication assumption")
		})
	}
}

func TestAssumedLocalUnixManagementDistinguishesNotApplicableFromUnknown(t *testing.T) {
	bound, flow := assumedManagedUnixTestBinding(t, nil, nil)
	for _, environment := range []configuration.Environment{
		{}, {V: &configuration.EnvironmentSsh{}}, {V: &configuration.EnvironmentLocal{}},
	} {
		flow.Environment = environment
		view, err := bound.UnixAccountWithManagement(t.Context(), flow)
		require.NoError(t, err)
		managed, present, err := view.GetField("managed")
		require.NoError(t, err)
		require.True(t, present)
		require.Nil(t, managed, "a non-applicable capability is nil, not false or an unmodeled observation")
	}
}

func TestAssumedLocalUnixManagementViewsOwnTheirObservation(t *testing.T) {
	bound, flow := assumedManagedUnixTestBinding(t, &user.Group{Name: "managed"}, &user.Groups{})
	first, err := bound.UnixAccountWithManagement(t.Context(), flow)
	require.NoError(t, err)
	flow.Environment.V.(*configuration.EnvironmentLocal).ManagedGroup = "other"
	second, err := bound.UnixAccountWithManagement(t.Context(), flow)
	require.NoError(t, err)
	firstManaged, _, err := first.GetField("managed")
	require.NoError(t, err)
	secondManaged, _, err := second.GetField("managed")
	require.NoError(t, err)
	require.Equal(t, true, firstManaged)
	require.Equal(t, false, secondManaged)
	for range 8 {
		t.Run("reader", func(t *testing.T) {
			t.Parallel()
			value, _, err := first.GetField("managed")
			require.NoError(t, err)
			require.Equal(t, true, value)
			groups, _, err := second.GetField("groups")
			require.NoError(t, err)
			require.Empty(t, groups)
		})
	}
}

func TestAssumedLocalUnixManagementRejectsWrongBindingsAndContexts(t *testing.T) {
	bound, flow := assumedManagedUnixTestBinding(t, &user.Group{Name: "managed"}, nil)
	otherName := *flow
	otherName.Name = "other"
	otherReference := *flow
	otherReference.Authorization.Reference = "other"
	wrongType := *flow
	wrongType.Authorization.V = &configuration.AuthorizationNone{}
	for _, flow := range []*configuration.Flow{nil, &otherName, &otherReference, &wrongType} {
		view, err := bound.UnixAccountWithManagement(t.Context(), flow)
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
		require.True(t, errors.Config.IsErr(err))
		require.Nil(t, view)
	}
	for _, bound := range []*AssumedLocalAuthentication{nil, {}} {
		_, err := bound.UnixAccountWithManagement(t.Context(), flow)
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
	}
	windowsLookup, _ := assumedLocalWindowsTestLookup(t)
	windowsBinding, err := BindAssumedLocalWindowsAuthentication(t.Context(), flow, "canonical", windowsLookup)
	require.NoError(t, err)
	_, err = windowsBinding.UnixAccountWithManagement(t.Context(), flow)
	require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption, "Windows observations must not be treated as Unix membership")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelDeadline := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	for _, ctx := range []context.Context{nil, canceled, expired} {
		view, err := bound.UnixAccountWithManagement(ctx, flow)
		require.True(t, errors.System.IsErr(err))
		require.Nil(t, view)
		if ctx != nil {
			require.ErrorIs(t, err, ctx.Err())
		}
	}
}
