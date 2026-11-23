//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

// Checked against the original local resolver before sharing its lookup and
// projection paths. The v1 hash binds selectors, not the current account's UID.
func TestLocalUnixTargetCompatibilityVectors(t *testing.T) {
	zero := user.Id(0)
	for _, test := range []struct {
		label, name string
		uid         *user.Id
		account     *user.User
		canonical   string
	}{
		{"existing name", "alias", nil, &user.User{Name: "canonical", Uid: 1234}, "canonical"},
		{"absent name", "absent", nil, nil, "absent"},
		{"existing UID zero", "", &zero, &user.User{Name: "explicit-zero", Uid: 0}, "explicit-zero"},
		{"absent UID zero", "", &zero, nil, ""},
		{"name still takes precedence over requested UID", "alias", &zero, &user.User{Name: "canonical", Uid: 1234}, "canonical"},
	} {
		t.Run(test.label, func(t *testing.T) {
			conf := &configuration.EnvironmentLocal{}
			require.NoError(t, conf.SetDefaults())
			conf.User = configuration.UserRequirementTemplate{
				Name: template.MustNewString(test.name), DisplayName: template.MustNewString("Display"),
				Group: configuration.GroupRequirementTemplate{Name: template.MustNewString("primary")},
				Groups: configuration.GroupRequirementTemplates{
					{Name: template.MustNewString("second")}, {Name: template.MustNewString("first")},
				},
				Shell: template.MustNewString("/bin/sh"), HomeDir: template.MustNewString("/fixture/home"), Skel: template.MustNewString("/fixture/skel"),
			}
			if test.uid != nil {
				value := template.MustNewTextMarshaller[user.Id](test.uid.String())
				conf.User.Uid = &value
			}
			conf.ShellCommand = template.MustNewStrings("/bin/sh", "-l")
			conf.ExecCommandPrefix = template.MustNewStrings("/usr/bin/env")
			conf.Directory = template.MustNewString("/fixture/work")
			conf.PortForwardingAllowed = template.BoolOf(false)
			repository := &LocalRepository{conf: conf, userRepository: &targetTestUsers{account: test.account}}
			actual, err := repository.ResolveSessionTarget(targetTestContext{ctx: t.Context()})
			require.NoError(t, err)
			selector, err := json.Marshal(user.Requirement{
				Name: test.canonical, DisplayName: "Display", Uid: test.uid, Group: user.GroupRequirement{Name: "primary"},
				Groups: user.GroupRequirements{{Name: "second"}, {Name: "first"}},
				Shell:  "/bin/sh", HomeDir: "/fixture/home", Skel: "/fixture/skel",
			})
			require.NoError(t, err)
			expected, err := session.NewTarget("local-unix", map[string]string{
				"resolver": "environment-v1", "account": string(selector),
				"shellCommand": `["/bin/sh","-l"]`, "execCommandPrefix": `["/usr/bin/env"]`,
				"directory": "/fixture/work", "portForwardingAllowed": "false",
			})
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		})
	}
}

type localProjectionTestLookup struct {
	byName func(context.Context, string) (string, user.Id, error)
	byId   func(context.Context, user.Id) (string, user.Id, error)
}

func (this localProjectionTestLookup) LookupIdentityByName(ctx context.Context, name string) (string, user.Id, error) {
	return this.byName(ctx, name)
}
func (this localProjectionTestLookup) LookupIdentityById(ctx context.Context, id user.Id) (string, user.Id, error) {
	return this.byId(ctx, id)
}

func localProjectionTestConfiguration(t *testing.T, name string) *configuration.EnvironmentLocal {
	t.Helper()
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.User.Name = template.MustNewString(name)
	conf.LoginAllowed = template.MustNewBool(`{{ fail "login is a different policy stage" }}`)
	conf.CreateIfAbsent = template.MustNewBool(`{{ fail "must not evaluate provisioning" }}`)
	return conf
}

func TestLocalUnixProjectionUsesOnlyExplicitFactsAndPreservesDeferredCreation(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context(), principal: "synthetic"}
	conf := localProjectionTestConfiguration(t, `{{ .authentication.principal }}`)
	absent, err := user.NewMemoryLookup(user.AccountLookupFacts{AbsentNames: []string{"synthetic"}})
	require.NoError(t, err)
	before, err := ProjectLocalUnixTarget(ctx, conf, absent)
	require.NoError(t, err)
	uid := user.Id(1234)
	account, err := user.NewSnapshot(user.AccountFacts{Name: "synthetic", Uid: &uid})
	require.NoError(t, err)
	present, err := user.NewMemoryLookup(user.AccountLookupFacts{Accounts: []*user.Snapshot{account}})
	require.NoError(t, err)
	after, err := ProjectLocalUnixTarget(ctx, conf, present)
	require.NoError(t, err)
	beforeTarget, err := before.SessionTarget()
	require.NoError(t, err)
	afterTarget, err := after.SessionTarget()
	require.NoError(t, err)
	require.Equal(t, beforeTarget, afterTarget, "the current UID must not change a name-based v1 fingerprint")
	require.Equal(t, "local-unix", after.Kind())
	requireProjectionField(t, after, "shellCommand", []string{})
	requireProjectionField(t, after, "portForwardingAllowed", true)
	selector, found := after.Field("account")
	require.True(t, found)
	var requested user.Requirement
	require.NoError(t, json.Unmarshal([]byte(selector.(string)), &requested))
	require.Equal(t, "synthetic", requested.Name)
	require.Nil(t, requested.Uid, "a name-based selector must not acquire an assumed current UID")

	unknown, err := user.NewMemoryLookup(user.AccountLookupFacts{})
	require.NoError(t, err)
	projection, err := ProjectLocalUnixTarget(ctx, conf, unknown)
	require.ErrorIs(t, err, user.ErrAccountNotModeled)
	require.Equal(t, TargetProjection{}, projection)
}

func TestLocalUnixProjectionEvaluatesOnceAndPreservesNamePrecedence(t *testing.T) {
	ctx := &projectionCountingContext{targetTestContext: targetTestContext{ctx: t.Context()}}
	conf := localProjectionTestConfiguration(t, `{{ .counted }}`)
	configuredUid := template.MustNewTextMarshaller[user.Id]("0")
	conf.User.Uid = &configuredUid
	calls := 0
	lookup := localProjectionTestLookup{
		byName: func(context.Context, string) (string, user.Id, error) { calls++; return "canonical", 1234, nil },
		byId:   func(context.Context, user.Id) (string, user.Id, error) { panic("a configured name takes precedence") },
	}
	projection, err := ProjectLocalUnixTarget(ctx, conf, lookup)
	require.NoError(t, err)
	for range 3 {
		_, err := projection.SessionTarget()
		require.NoError(t, err)
		_, found := projection.Field("account")
		require.True(t, found)
	}
	require.Equal(t, 1, calls)
	require.Equal(t, 1, ctx.calls)
	conf.User.Name = template.MustNewString("")
	lookup.byId = func(_ context.Context, id user.Id) (string, user.Id, error) {
		require.Equal(t, user.Id(0), id)
		return "explicit-zero", 0, nil
	}
	_, err = ProjectLocalUnixTarget(ctx, conf, lookup)
	require.NoError(t, err)
	lookup.byId = func(context.Context, user.Id) (string, user.Id, error) { return "wrong-identity", 42, nil }
	_, err = ProjectLocalUnixTarget(ctx, conf, lookup)
	require.ErrorIs(t, err, user.ErrInvalidAccountFacts)
}

type localNilSuccessUsers struct{ user.CloseableRepository }

func (localNilSuccessUsers) LookupByName(context.Context, string) (*user.User, error) {
	return nil, nil
}
func (localNilSuccessUsers) LookupById(context.Context, user.Id) (*user.User, error) { return nil, nil }

func TestLocalUnixProjectionRejectsMissingInvalidOrFailedDependencies(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	conf := localProjectionTestConfiguration(t, "sensitive-account")
	secret := errors.New("sensitive-provider-error")
	for _, test := range []struct {
		name, account string
		err           error
		category      error
	}{
		{"unmodeled", "", user.ErrAccountNotModeled, user.ErrAccountNotModeled},
		{"unavailable", "", user.ErrAccountLookupUnavailable, user.ErrAccountLookupUnavailable},
		{"invalid facts", "", user.ErrInvalidAccountFacts, user.ErrInvalidAccountFacts},
		{"source canceled", "", context.Canceled, context.Canceled},
		{"source deadline", "", context.DeadlineExceeded, context.DeadlineExceeded},
		{"ambiguous absence", "", errors.Join(user.ErrAccountNotModeled, user.ErrNoSuchUser), user.ErrAccountNotModeled},
		{"provider failure", "", secret, nil},
		{"empty successful identity", "", nil, user.ErrInvalidAccountFacts},
	} {
		t.Run(test.name, func(t *testing.T) {
			lookup := localProjectionTestLookup{byName: func(context.Context, string) (string, user.Id, error) { return test.account, 0, test.err }}
			projection, err := ProjectLocalUnixTarget(ctx, conf, lookup)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "sensitive")
			require.False(t, errors.Is(err, secret), "sensitive provider causes must not be retained")
			if test.category != nil {
				require.ErrorIs(t, err, test.category)
			}
			require.Equal(t, TargetProjection{}, projection)
		})
	}
	for _, lookup := range []user.IdentityLookup{nil, (*user.MemoryLookup)(nil), &user.MemoryLookup{}} {
		projection, err := ProjectLocalUnixTarget(ctx, conf, lookup)
		require.ErrorIs(t, err, user.ErrAccountLookupUnavailable)
		require.Equal(t, TargetProjection{}, projection)
	}
	_, err := ProjectLocalUnixTarget(ctx, nil, localProjectionTestLookup{})
	require.Error(t, err)
	require.True(t, berrors.Config.IsErr(err))
	failedRender := *conf
	failedRender.User.Name = template.MustNewString(`{{ fail "sensitive-template-error" }}`)
	_, err = ProjectLocalUnixTarget(ctx, &failedRender, localProjectionTestLookup{})
	require.Error(t, err)
	require.True(t, berrors.Config.IsErr(err))
	require.NotContains(t, err.Error(), "sensitive")

	// A repository returning nil success must not imply absence or a valid
	// legacy session. No lookup, credential or management methods are available.
	bad := &LocalRepository{conf: conf, userRepository: localNilSuccessUsers{}}
	_, err = bad.ResolveSessionTarget(ctx)
	require.ErrorIs(t, err, user.ErrInvalidAccountFacts)
	bad.userRepository = nil
	_, err = bad.ResolveSessionTarget(ctx)
	require.ErrorIs(t, err, user.ErrAccountLookupUnavailable)
}

func TestLocalUnixProjectionCancellationDoesNotBecomeAbsence(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conf := localProjectionTestConfiguration(t, "synthetic")
	calls := 0
	lookup := localProjectionTestLookup{byName: func(context.Context, string) (string, user.Id, error) {
		calls++
		cancel()
		return "", 0, user.ErrNoSuchUser
	}}
	projection, err := ProjectLocalUnixTarget(targetTestContext{ctx: ctx}, conf, lookup)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, berrors.System.IsErr(err))
	require.Equal(t, TargetProjection{}, projection)
	_, err = ProjectLocalUnixTarget(targetTestContext{ctx: ctx}, conf, lookup)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
	_, err = ProjectLocalUnixTarget(targetTestContext{}, conf, lookup)
	require.ErrorIs(t, err, user.ErrAccountLookupUnavailable)
	var typedNil *targetTestContext
	_, err = ProjectLocalUnixTarget(typedNil, conf, lookup)
	require.ErrorIs(t, err, user.ErrAccountLookupUnavailable)
}

func TestLocalUnixProjectionPreservesLookupErrorTypesWithoutCauses(t *testing.T) {
	ctx := targetTestContext{ctx: t.Context()}
	conf := localProjectionTestConfiguration(t, "fixture")
	for _, category := range []berrors.Type{berrors.Unknown, berrors.Config, berrors.System, berrors.Network, berrors.User, berrors.Permission, berrors.Expired} {
		t.Run(category.String(), func(t *testing.T) {
			secret := category.Newf("sensitive-provider-details")
			lookup := localProjectionTestLookup{byName: func(context.Context, string) (string, user.Id, error) { return "", 0, secret }}
			projection, err := ProjectLocalUnixTarget(ctx, conf, lookup)
			typed, ok := berrors.IsError(err)
			require.True(t, ok)
			require.Equal(t, category, typed.Type)
			require.NotContains(t, err.Error(), "sensitive")
			require.Nil(t, errors.Unwrap(err))
			require.False(t, errors.Is(err, secret))
			require.Equal(t, TargetProjection{}, projection)
		})
	}
	for _, test := range []struct {
		sentinel error
		category berrors.Type
	}{
		{user.ErrAccountNotModeled, berrors.Config},
		{user.ErrInvalidAccountFacts, berrors.Config},
		{user.ErrAccountLookupUnavailable, berrors.System},
		{context.Canceled, berrors.System},
		{context.DeadlineExceeded, berrors.System},
	} {
		lookup := localProjectionTestLookup{byName: func(context.Context, string) (string, user.Id, error) {
			return "", 0, fmt.Errorf("sensitive wrapper: %w", test.sentinel)
		}}
		_, err := ProjectLocalUnixTarget(ctx, conf, lookup)
		require.ErrorIs(t, err, test.sentinel)
		require.True(t, test.category.IsErr(err))
		require.True(t, errors.Unwrap(err) == test.sentinel)
		require.NotContains(t, err.Error(), "sensitive")
	}
}
