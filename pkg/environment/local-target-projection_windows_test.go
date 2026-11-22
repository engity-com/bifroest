//go:build windows

package environment

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type windowsProjectionTestLookup struct {
	byName func(context.Context, string) (string, string, error)
	bySID  func(context.Context, string) (string, string, error)
}

func (this windowsProjectionTestLookup) LookupIdentityByName(ctx context.Context, name string) (string, string, error) {
	return this.byName(ctx, name)
}
func (this windowsProjectionTestLookup) LookupIdentityBySID(ctx context.Context, sid string) (string, string, error) {
	return this.bySID(ctx, sid)
}

func windowsProjectionTestConfiguration(name, sid string) *configuration.EnvironmentLocal {
	// Explicit values, not COMSPEC/host-dependent shell defaults.
	return &configuration.EnvironmentLocal{
		WindowsUserRequirementTemplate: configuration.WindowsUserRequirementTemplate{
			Name: template.MustNewString(name), Uid: template.MustNewString(sid), DisplayName: template.MustNewString("Display"),
			Skel: template.MustNewString(`C:\fixture\skel`),
			Groups: configuration.WindowsUserGroupRequirementTemplates{
				{Name: template.MustNewString("second")},
				{Gid: template.MustNewString("S-1-5-32-545")},
			},
		},
		EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{
			ShellCommand: template.MustNewStrings(`C:\fixture\shell.exe`), ExecCommandPrefix: template.MustNewStrings(`C:\fixture\shell.exe`, "/C"),
			Directory: template.MustNewString(`C:\fixture\work`), PortForwardingAllowed: template.BoolOf(false),
			LoginAllowed: template.MustNewBool(`{{ fail "not the login stage" }}`), CreateIfAbsent: template.MustNewBool(`{{ fail "must not provision" }}`),
		},
	}
}

// Explicit legacy field sets, not a second production resolver. These tests use
// only modeled account facts and SID text conversion, never native accounts.
func TestLocalWindowsTargetCompatibilityVectors(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	account, err := windowslocal.NewAccountSnapshot(windowslocal.AccountFacts{Identity: windowslocal.Account{Name: "alice", SID: sid}})
	require.NoError(t, err)
	lookup, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{
		Accounts: []*windowslocal.AccountSnapshot{account}, AbsentNames: []string{"absent"}, AbsentSIDs: []string{"S-1-5-18", "S-1-5-32-544"},
	})
	require.NoError(t, err)
	for _, test := range []struct{ label, name, uid, canonicalName, canonicalSID string }{
		{"existing name", "ALICE", "", "alice", ""},
		{"absent name", "absent", "", "absent", ""},
		{"existing SID", "", sid, "alice", sid},
		{"absent SID", "", "S-1-5-18", "", "S-1-5-18"},
		{"matching name and SID", "ALICE", sid, "alice", sid},
		{"absent name with existing SID has no fallback", "absent", sid, "absent", sid},
		{"existing SID text alias normalization", "", "BA", "", "S-1-5-32-544"},
	} {
		t.Run(test.label, func(t *testing.T) {
			conf := windowsProjectionTestConfiguration(test.name, test.uid)
			projection, err := ProjectLocalWindowsTarget(targetTestContext{ctx: t.Context()}, conf, lookup)
			require.NoError(t, err)
			actual, err := projection.SessionTarget()
			require.NoError(t, err)
			expected, err := session.NewTarget("local-windows", map[string]string{
				"resolver": "environment-v1", "name": test.canonicalName, "requestedSID": test.canonicalSID,
				"shellCommand": `["C:\\fixture\\shell.exe"]`, "execCommandPrefix": `["C:\\fixture\\shell.exe","/C"]`,
				"directory": `C:\fixture\work`, "portForwardingAllowed": "false", "displayName": "Display", "skel": `C:\fixture\skel`,
				"groups": `[{"Name":"second","Gid":""},{"Name":"","Gid":"S-1-5-32-545"}]`,
			})
			require.NoError(t, err)
			require.Equal(t, expected, actual)
			require.Equal(t, "local-windows", projection.Kind())
			requireProjectionField(t, projection, "requestedSID", test.canonicalSID)
			requireProjectionField(t, projection, "shellCommand", []string{`C:\fixture\shell.exe`})
			requireProjectionField(t, projection, "portForwardingAllowed", false)
		})
	}
}

func TestLocalWindowsProjectionKeepsCurrentSIDSeparateAndEvaluatesOnce(t *testing.T) {
	conf := windowsProjectionTestConfiguration("alice", "")
	conf.DisplayName = template.MustNewString(`{{ .counted }}`)
	ctx := &projectionCountingContext{targetTestContext: targetTestContext{ctx: t.Context()}}
	nameCalls := 0
	lookup := windowsProjectionTestLookup{byName: func(context.Context, string) (string, string, error) {
		nameCalls++
		return "Alice", fmt.Sprintf("S-1-5-21-1-2-3-%d", nameCalls), nil
	}}
	first, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.NoError(t, err)
	for range 3 {
		_, err := first.SessionTarget()
		require.NoError(t, err)
		requireProjectionField(t, first, "name", "alice")
	}
	require.Equal(t, 1, nameCalls)
	require.Equal(t, 1, ctx.calls)
	second, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.NoError(t, err)
	firstTarget, err := first.SessionTarget()
	require.NoError(t, err)
	secondTarget, err := second.SessionTarget()
	require.NoError(t, err)
	require.Equal(t, firstTarget, secondTarget, "a current SID is not a configured name-only selector")
	conf.DisplayName = template.MustNewString("caller mutation")
	requireProjectionField(t, first, "displayName", "example.invalid/diagnostics:approved")
}

func TestLocalWindowsProjectionRejectsInvalidInputsBeforeLookup(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	for _, conf := range []*configuration.EnvironmentLocal{
		nil, windowsProjectionTestConfiguration("", ""), windowsProjectionTestConfiguration(`DOMAIN\alice`, ""),
		windowsProjectionTestConfiguration("alice@domain", ""), windowsProjectionTestConfiguration("alice", "sensitive-invalid-sid"),
		windowsProjectionTestConfiguration(`{{ fail "sensitive-template-error" }}`, ""),
	} {
		projection, err := ProjectLocalWindowsTarget(ctx, conf, windowsProjectionTestLookup{})
		require.True(t, berrors.Config.IsErr(err), "%v", err)
		require.NotContains(t, err.Error(), "sensitive")
		require.Equal(t, TargetProjection{}, projection)
	}
	for _, lookup := range []windowslocal.IdentityLookup{nil, (*windowslocal.MemoryLookup)(nil), &windowslocal.MemoryLookup{}} {
		_, err := ProjectLocalWindowsTarget(ctx, windowsProjectionTestConfiguration("alice", ""), lookup)
		require.ErrorIs(t, err, windowslocal.ErrAccountLookupUnavailable)
		require.True(t, berrors.System.IsErr(err))
	}
	var typedNil *targetTestContext
	for _, ctx := range []Context{nil, typedNil, targetTestContext{}} {
		_, err := ProjectLocalWindowsTarget(ctx, windowsProjectionTestConfiguration("alice", ""), windowsProjectionTestLookup{})
		require.ErrorIs(t, err, windowslocal.ErrAccountLookupUnavailable)
	}
}

func TestLocalWindowsProjectionRejectsUnknownFactsAndRetainsSafeErrorTypes(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	conf := windowsProjectionTestConfiguration("alice", "")
	for _, sentinel := range []error{windowslocal.ErrAccountNotModeled, windowslocal.ErrAccountLookupUnavailable, windowslocal.ErrInvalidAccountFacts, context.Canceled, context.DeadlineExceeded} {
		lookup := windowsProjectionTestLookup{byName: func(context.Context, string) (string, string, error) {
			return "", "", errors.Join(fmt.Errorf("sensitive: %w", sentinel), windowslocal.ErrNotFound)
		}}
		projection, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
		require.ErrorIs(t, err, sentinel)
		require.False(t, errors.Is(err, windowslocal.ErrNotFound), "failure must not become absence")
		require.NotContains(t, err.Error(), "sensitive")
		require.Equal(t, TargetProjection{}, projection)
	}
	for _, category := range []berrors.Type{berrors.Unknown, berrors.Config, berrors.System, berrors.Network, berrors.User, berrors.Permission, berrors.Expired} {
		secret := category.Newf("sensitive-provider-error")
		lookup := windowsProjectionTestLookup{byName: func(context.Context, string) (string, string, error) { return "", "", secret }}
		_, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
		typed, ok := berrors.IsError(err)
		require.True(t, ok)
		require.Equal(t, category, typed.Type)
		require.NotContains(t, err.Error(), "sensitive")
		require.Nil(t, errors.Unwrap(err))
		require.False(t, errors.Is(err, secret))
	}
	lookup := windowsProjectionTestLookup{byName: func(context.Context, string) (string, string, error) { return "alice", "S-1-5-21-1-2-3-1001", nil }}
	conf.Uid = template.MustNewString("S-1-5-21-1-2-3-1002")
	_, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.ErrorIs(t, err, windowslocal.ErrInvalidAccountFacts)
	require.True(t, berrors.Config.IsErr(err))
}

func TestLocalWindowsProjectionCancellationDoesNotBecomeAbsence(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	lookup := windowsProjectionTestLookup{byName: func(context.Context, string) (string, string, error) {
		calls++
		cancel()
		return "", "", windowslocal.ErrNotFound
	}}
	conf := windowsProjectionTestConfiguration("alice", "")
	projection, err := ProjectLocalWindowsTarget(targetTestContext{ctx: ctx}, conf, lookup)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, berrors.System.IsErr(err))
	require.Equal(t, TargetProjection{}, projection)
	_, err = ProjectLocalWindowsTarget(targetTestContext{ctx: ctx}, conf, lookup)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}

func TestLocalWindowsProjectionRetainsTemplateScopesAndSanitizesGroups(t *testing.T) {
	lookup, err := windowslocal.NewMemoryLookup(windowslocal.AccountLookupFacts{AbsentNames: []string{"fixture"}})
	require.NoError(t, err)
	conf := windowsProjectionTestConfiguration(`{{ env "ACCOUNT" }}`, "")
	conf.Groups = configuration.WindowsUserGroupRequirementTemplates{{Name: template.MustNewString(`{{ env "GROUP" }}`)}}
	ctx := projectionEvaluationTestContext{
		targetTestContext: targetTestContext{ctx: t.Context()},
		evaluation: template.NewEvaluation(template.EvaluationSources{LookupEnv: func(key string) (string, bool, error) {
			if key == "ACCOUNT" {
				return "fixture", true, nil
			}
			return "group", true, nil
		}}),
	}
	projection, err := ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.NoError(t, err)
	requireProjectionField(t, projection, "groups", `[{"Name":"group","Gid":""}]`)
	ctx.evaluation = template.NewEvaluation(template.EvaluationSources{})
	_, err = ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.True(t, berrors.Config.IsErr(err))
	require.NotContains(t, err.Error(), "ACCOUNT")

	conf.Name = template.MustNewString("fixture")
	conf.Groups[0].Name = template.MustNewString(`{{ fail "sensitive-group-error" }}`)
	projection, err = ProjectLocalWindowsTarget(ctx, conf, lookup)
	require.True(t, berrors.Config.IsErr(err))
	require.NotContains(t, err.Error(), "sensitive")
	require.Nil(t, errors.Unwrap(err))
	require.Equal(t, TargetProjection{}, projection)
}

func TestLocalWindowsLookupAdapterCopiesOnlyIdentity(t *testing.T) {
	name, sid, err := localWindowsLookupIdentity(windowsLocalAccount{
		Name: "alice", SID: "S-1-5-21-1-2-3-1001", DisplayName: "not part of the boundary",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "alice", name)
	require.Equal(t, "S-1-5-21-1-2-3-1001", sid)
	_, _, err = localWindowsLookupIdentity(windowsLocalAccount{}, fmt.Errorf("sensitive: %w", errLocalWindowsAccountNotFound))
	require.ErrorIs(t, err, windowslocal.ErrNotFound)
	require.NotContains(t, err.Error(), "sensitive")
	providerErr := berrors.Network.Newf("provider unavailable")
	_, _, err = localWindowsLookupIdentity(windowsLocalAccount{}, providerErr)
	require.ErrorIs(t, err, providerErr)
	require.True(t, berrors.Network.IsErr(err))
}
