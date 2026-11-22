//go:build unix || windows

package authorization

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

func assumedLocalTestFlow() *configuration.Flow {
	return &configuration.Flow{
		Name:          "flow",
		Authorization: configuration.Authorization{V: &configuration.AuthorizationLocal{}, Reference: "local-authentication"},
	}
}

func assumedLocalWindowsTestLookup(t *testing.T) (*windowslocal.MemoryLookup, *windowslocal.AccountSnapshot) {
	t.Helper()
	home, shell := `C:\fixture\home`, `C:\fixture\shell.exe`
	groups := []windowslocal.AccountGroupFacts{{Name: "operators", SID: "S-1-5-32-545"}}
	account, err := windowslocal.NewAccountSnapshot(windowslocal.AccountFacts{
		Identity: windowslocal.Account{Name: "canonical", SID: "S-1-5-21-1-2-3-1001"},
		HomeDir:  &home, Shell: &shell, Groups: &groups,
	})
	require.NoError(t, err)
	lookup, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{Accounts: []*windowslocal.AccountSnapshot{account}, AbsentNames: []string{"absent"}})
	require.NoError(t, err)
	return lookup, account
}

func TestAssumedLocalWindowsAuthenticationDerivesIdentityAndOwnsItsAccount(t *testing.T) {
	flow := assumedLocalTestFlow()
	lookup, supplied := assumedLocalWindowsTestLookup(t)
	bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), flow, "CANONICAL", lookup)
	require.NoError(t, err)
	expected := localAuthenticationIdentity("canonical", "S-1-5-21-1-2-3-1001")
	identity, err := bound.Authentication()
	require.NoError(t, err)
	require.Equal(t, expected, identity)
	require.Equal(t, configuration.FlowName("flow"), bound.Flow())
	require.Equal(t, "local-authentication", bound.AuthorizationReference())

	// Neither an outer snapshot/lookup replacement nor a configuration mutation
	// may turn the binding into another identity or give it runtime capabilities.
	*supplied = windowslocal.AccountSnapshot{}
	*lookup = windowslocal.MemoryLookup{}
	flow.Name, flow.Authorization.Reference, flow.Authorization.V = "changed", "changed", &configuration.AuthorizationNone{}
	identity.Principal, identity.Subject = "caller mutation", "caller mutation"
	actual, err := bound.Authentication()
	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, configuration.FlowName("flow"), bound.Flow())
	require.Equal(t, "local-authentication", bound.AuthorizationReference())
	view, err := bound.Account()
	require.NoError(t, err)
	for field, expected := range map[string]any{
		"name": "canonical", "uid": "S-1-5-21-1-2-3-1001", "homeDir": `C:\fixture\home`, "shell": `C:\fixture\shell.exe`,
		"gids": []string{"S-1-5-32-545"},
	} {
		value, present, err := view.GetField(field)
		require.NoError(t, err)
		require.True(t, present)
		require.Equal(t, expected, value)
	}
	_, native := any(view).(windowslocal.PasswordAccountView)
	require.False(t, native)
	_, raw := any(view).(*windowslocal.AccountSnapshot)
	require.False(t, raw, "do not expose a caller-replaceable snapshot pointer")
	_, authorization := any(bound).(Authorization)
	require.False(t, authorization, "assumed facts must not themselves authorize a production request")
}

func TestAssumedLocalAuthenticationNeverInfersManagementOrNativeMetadata(t *testing.T) {
	account, err := windowslocal.NewAccountSnapshot(windowslocal.AccountFacts{Identity: windowslocal.Account{Name: "fixture", SID: "S-1-5-21-1-2-3-1001"}})
	require.NoError(t, err)
	lookup, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{Accounts: []*windowslocal.AccountSnapshot{account}})
	require.NoError(t, err)
	bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), "fixture", lookup)
	require.NoError(t, err)
	view, err := bound.Account()
	require.NoError(t, err)
	for _, field := range []string{"managed", "homeDir", "shell", "groups", "gids", "displayName", "unknown"} {
		value, present, err := view.GetField(field)
		require.Error(t, err)
		require.True(t, errors.Config.IsErr(err))
		require.Nil(t, value)
		require.False(t, present)
		if field == "managed" {
			require.ErrorIs(t, err, ErrAssumedLocalFieldUnavailable)
		}
	}
}

func TestAssumedLocalAuthenticationRejectsUnsupportedOrMissingBindings(t *testing.T) {
	for _, flow := range []*configuration.Flow{
		nil, {}, {Name: "../invalid", Authorization: configuration.Authorization{V: &configuration.AuthorizationLocal{}}},
		{Name: "flow"}, {Name: "flow", Authorization: configuration.Authorization{V: (*configuration.AuthorizationLocal)(nil)}},
		{Name: "flow", Authorization: configuration.Authorization{V: &configuration.AuthorizationNone{}}},
		{Name: "flow", Authorization: configuration.Authorization{V: &configuration.AuthorizationOidcDeviceAuth{}}},
	} {
		bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), flow, "canonical", nil)
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
		require.True(t, errors.Config.IsErr(err))
		require.Nil(t, bound)
	}
	lookup, _ := assumedLocalWindowsTestLookup(t)
	for _, name := range []string{"", `DOMAIN\canonical`, "canonical@domain"} {
		_, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), name, lookup)
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
	}
	for _, name := range []string{strings.Repeat("x", 1025), "fixture"} {
		sid := "S-1-5-21-1-2-3-1001"
		if name == "fixture" {
			sid = strings.Repeat("x", 1025)
		}
		account, err := windowslocal.NewAccountSnapshot(windowslocal.AccountFacts{Identity: windowslocal.Account{Name: name, SID: sid}})
		require.NoError(t, err)
		lookup, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{Accounts: []*windowslocal.AccountSnapshot{account}})
		require.NoError(t, err)
		_, err = BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), name, lookup)
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
	}
}

func TestAssumedLocalAuthenticationPreservesLookupStatesAndCancellation(t *testing.T) {
	lookup, _ := assumedLocalWindowsTestLookup(t)
	for _, test := range []struct {
		name string
		err  error
	}{
		{"absent", windowslocal.ErrNotFound}, {"unknown", windowslocal.ErrAccountNotModeled},
	} {
		bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), test.name, lookup)
		require.ErrorIs(t, err, test.err)
		require.Nil(t, bound)
	}
	for _, source := range []*windowslocal.MemoryLookup{nil, {}} {
		_, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), "canonical", source)
		require.ErrorIs(t, err, windowslocal.ErrAccountLookupUnavailable)
		require.True(t, errors.System.IsErr(err))
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, cancelDeadline := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	for _, test := range []struct {
		ctx context.Context
		err error
	}{
		{nil, windowslocal.ErrAccountLookupUnavailable}, {canceled, context.Canceled}, {expired, context.DeadlineExceeded},
	} {
		bound, err := BindAssumedLocalWindowsAuthentication(test.ctx, assumedLocalTestFlow(), "canonical", lookup)
		require.ErrorIs(t, err, test.err)
		require.True(t, errors.System.IsErr(err))
		require.Nil(t, bound)
	}
	for _, bound := range []*AssumedLocalAuthentication{nil, {}} {
		identity, err := bound.Authentication()
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
		require.Equal(t, authentication.Identity{}, identity)
		view, err := bound.Account()
		require.ErrorIs(t, err, ErrInvalidLocalAuthenticationAssumption)
		require.Nil(t, view)
	}
}

// The explicit test-only adapter is deliberate: a bound assumption alone is not
// an Authorization, and no production factory/registration can select it.
type assumedLocalBindingTestAuthorization struct {
	Authorization
	binding *AssumedLocalAuthentication
}

func (assumedLocalBindingTestAuthorization) IsAuthorized() bool { return true }
func (this assumedLocalBindingTestAuthorization) Flow() configuration.FlowName {
	return this.binding.Flow()
}
func (this assumedLocalBindingTestAuthorization) Authentication() (authentication.Identity, error) {
	return this.binding.Authentication()
}
func (this assumedLocalBindingTestAuthorization) GetField(name string, _ ContextEnabled) (any, bool, error) {
	if name == "user" {
		view, err := this.binding.Account()
		return view, err == nil, err
	}
	return nil, false, ErrAssumedLocalFieldUnavailable
}

func TestAssumedLocalAuthenticationUsesSharedPrincipalEvaluation(t *testing.T) {
	lookup, _ := assumedLocalWindowsTestLookup(t)
	bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), "CANONICAL", lookup)
	require.NoError(t, err)
	auth := assumedLocalBindingTestAuthorization{binding: bound}
	flows := principalMappingTestFlows(`{{ .authentication.principal }}:{{ index .authorization.user.gids 0 }}:{{ env "SUFFIX" }}`)
	contextFor := func(identity authentication.Identity) PrincipalMappingContext {
		return principalEvaluationTestContext{
			principalMappingTestContext: newPrincipalMappingTestContext(t, identity, auth),
			evaluation:                  template.NewEvaluation(template.EvaluationSources{LookupEnv: func(string) (string, bool, error) { return "mapped", true, nil }}),
		}
	}
	identity, err := AuthenticationWithPrincipal(auth, flows, contextFor)
	require.NoError(t, err)
	require.Equal(t, "canonical:S-1-5-32-545:mapped", identity.Principal)
	require.Equal(t, "local", identity.Issuer)
	require.Equal(t, "S-1-5-21-1-2-3-1001", identity.Subject)
	original, err := bound.Authentication()
	require.NoError(t, err)
	require.Equal(t, "canonical", original.Principal)
	for _, mapping := range []string{`{{ .authorization.user.managed }}`, `{{ .authorization.user.displayName }}`} {
		identity, err := AuthenticationWithPrincipal(auth, principalMappingTestFlows(mapping), contextFor)
		require.Error(t, err)
		require.True(t, errors.Config.IsErr(err))
		require.Equal(t, authentication.Identity{}, identity)
	}
}

func TestAssumedLocalAuthenticationSupportsIndependentParallelViews(t *testing.T) {
	lookup, _ := assumedLocalWindowsTestLookup(t)
	for range 16 {
		t.Run("binding", func(t *testing.T) {
			t.Parallel()
			bound, err := BindAssumedLocalWindowsAuthentication(t.Context(), assumedLocalTestFlow(), "canonical", lookup)
			require.NoError(t, err)
			view, err := bound.Account()
			require.NoError(t, err)
			value, _, err := view.GetField("gids")
			require.NoError(t, err)
			value.([]string)[0] = "reader mutation"
			value, _, err = view.GetField("gids")
			require.NoError(t, err)
			require.Equal(t, []string{"S-1-5-32-545"}, value)
		})
	}
}
