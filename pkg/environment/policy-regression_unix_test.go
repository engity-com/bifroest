//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

type characterizationUsers struct {
	user.CloseableRepository
	account    *user.User
	err        error
	names, ids int
	onLookup   func()
}

func (this *characterizationUsers) LookupByName(context.Context, string) (*user.User, error) {
	this.names++
	if this.onLookup != nil {
		this.onLookup()
	}
	return this.account, this.err
}
func (this *characterizationUsers) LookupById(context.Context, user.Id) (*user.User, error) {
	this.ids++
	if this.onLookup != nil {
		this.onLookup()
	}
	return this.account, this.err
}

func TestPolicyRegressionUnixTargetSelectorsAndLookupPrecedence(t *testing.T) {
	for _, test := range []struct {
		label, name string
		uid         *user.Id
		account     *user.User
		absent      bool
		canonical   string
	}{
		{"existing name", "alias", nil, &user.User{Name: "canonical", Uid: 1234}, false, "canonical"},
		{"absent name", "absent", nil, nil, true, "absent"},
		{"UID zero", "", new(user.Id), &user.User{Name: "zero", Uid: 0}, false, "zero"},
		{"absent UID zero", "", new(user.Id), nil, true, ""},
		{"name plus differing UID", "alias", new(user.Id), &user.User{Name: "canonical", Uid: 1234}, false, "canonical"},
	} {
		t.Run(test.label, func(t *testing.T) {
			conf := &configuration.EnvironmentLocal{}
			require.NoError(t, conf.SetDefaults())
			conf.User.Name, conf.User.DisplayName = template.MustNewString(test.name), template.MustNewString("Display")
			conf.User.Group = configuration.GroupRequirementTemplate{Name: template.MustNewString("primary")}
			conf.User.Groups = configuration.GroupRequirementTemplates{{Name: template.MustNewString("second")}, {Name: template.MustNewString("first")}}
			conf.User.HomeDir, conf.User.Shell, conf.User.Skel = template.MustNewString("/home/fixture"), template.MustNewString("/bin/sh"), template.MustNewString("/skel")
			if test.uid != nil {
				uid := template.MustNewTextMarshaller[user.Id](test.uid.String())
				conf.User.Uid = &uid
			}
			users := &characterizationUsers{account: test.account}
			if test.absent {
				users.err = user.ErrNoSuchUser
			}
			actual, err := (&LocalRepository{conf: conf, userRepository: users}).ResolveSessionTarget(targetTestContext{ctx: t.Context()})
			require.NoError(t, err)
			raw, err := json.Marshal(user.Requirement{Name: test.canonical, DisplayName: "Display", Uid: test.uid, Group: user.GroupRequirement{Name: "primary"}, Groups: user.GroupRequirements{{Name: "second"}, {Name: "first"}}, HomeDir: "/home/fixture", Shell: "/bin/sh", Skel: "/skel"})
			require.NoError(t, err)
			expected, err := session.NewTarget("local-unix", map[string]string{"resolver": "environment-v1", "account": string(raw), "shellCommand": `[]`, "execCommandPrefix": `[]`, "directory": "", "portForwardingAllowed": "true"})
			require.NoError(t, err)
			require.Equal(t, expected, actual)
			require.Equal(t, 1, users.names+users.ids)
			require.Equal(t, test.name != "", users.names == 1)
		})
	}
}

// Only ErrNoSuchUser establishes absence. Nil success or a mismatched UID must
// produce neither a target fingerprint nor session compatibility.
func TestPolicyRegressionUnixTargetRejectsInvalidProviderAnswers(t *testing.T) {
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.User.Name = template.MustNewString("fixture")
	ctx := targetTestContext{ctx: t.Context()}
	for _, test := range []struct {
		label   string
		name    string
		uid     *user.Id
		account *user.User
	}{
		{label: "nil name result is not absence", name: "fixture"},
		{label: "empty name is invalid", name: "fixture", account: &user.User{Uid: 1234}},
		{label: "nil UID zero result is not absence", uid: new(user.Id)},
		{label: "UID zero must match", uid: new(user.Id), account: &user.User{Name: "different", Uid: 42}},
	} {
		t.Run(test.label, func(t *testing.T) {
			copyOfConf := *conf
			copyOfConf.User.Name = template.MustNewString(test.name)
			if test.uid != nil {
				uid := template.MustNewTextMarshaller[user.Id](test.uid.String())
				copyOfConf.User.Uid = &uid
			}
			users := &characterizationUsers{account: test.account}
			repo := &LocalRepository{conf: &copyOfConf, userRepository: users}
			target, err := repo.ResolveSessionTarget(ctx)
			require.Empty(t, target)
			require.ErrorIs(t, err, user.ErrInvalidAccountFacts)
			require.True(t, berrors.Config.IsErr(err))
			require.Equal(t, 1, users.names+users.ids)
			// The token method is deliberately unavailable. Invalid identity facts
			// must be rejected before an empty token could imply compatibility.
			compatible, err := repo.IsSessionCompatibleWith(ctx, struct{ session.Session }{})
			require.False(t, compatible)
			require.ErrorIs(t, err, user.ErrInvalidAccountFacts)
		})
	}
	t.Run("provider error retains only category", func(t *testing.T) {
		secret := berrors.Network.Newf("private-secret")
		_, err := (&LocalRepository{conf: conf, userRepository: &characterizationUsers{err: secret}}).ResolveSessionTarget(ctx)
		require.EqualError(t, err, "cannot inspect local session target account")
		require.NotErrorIs(t, err, secret)
		require.True(t, berrors.Network.IsErr(err))
	})
}

// Cancellation prevents further lookups and must not become success when a
// lookup subsequently reports not-found. Its sentinel remains detectable.
func TestPolicyRegressionUnixTargetCancellationStopsLookup(t *testing.T) {
	for _, test := range []struct {
		name         string
		deadline     bool
		duringLookup bool
	}{
		{name: "already canceled"},
		{name: "deadline already expired", deadline: true},
		{name: "canceled during a not-found lookup", duringLookup: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			want := context.Canceled
			if test.deadline {
				cancel()
				ctx, cancel = context.WithDeadline(t.Context(), time.Unix(1, 0))
				want = context.DeadlineExceeded
			}
			defer cancel()
			users := &characterizationUsers{err: user.ErrNoSuchUser}
			wantCalls := 0
			if test.duringLookup {
				users.onLookup = cancel
				wantCalls = 1
			} else {
				cancel()
			}
			conf := &configuration.EnvironmentLocal{}
			require.NoError(t, conf.SetDefaults())
			conf.User.Name = template.MustNewString("fixture")
			target, err := (&LocalRepository{conf: conf, userRepository: users}).ResolveSessionTarget(targetTestContext{ctx: ctx})
			require.Empty(t, target)
			require.ErrorIs(t, err, want)
			require.True(t, berrors.System.IsErr(err))
			require.Equal(t, wantCalls, users.names)
			require.Zero(t, users.ids)
		})
	}
}

func TestPolicyRegressionUnixTargetSessionCompatibility(t *testing.T) {
	uid, replaced := user.Id(1234), user.Id(5678)
	for _, test := range []struct {
		label             string
		stored            localTokenUser
		account           *user.User
		empty, compatible bool
	}{
		{label: "no token", empty: true, compatible: true},
		{label: "matching UID", stored: localTokenUser{Name: "fixture", Uid: &uid}, account: &user.User{Name: "fixture", Uid: uid}, compatible: true},
		{label: "replaced UID", stored: localTokenUser{Name: "fixture", Uid: &uid}, account: &user.User{Name: "fixture", Uid: replaced}},
		{label: "different stored name", stored: localTokenUser{Name: "other", Uid: &uid}, account: &user.User{Name: "fixture", Uid: uid}},
		{label: "legacy name only", stored: localTokenUser{Name: "fixture"}, account: &user.User{Name: "fixture", Uid: uid}, compatible: true},
		{label: "missing current account", stored: localTokenUser{Name: "fixture", Uid: &uid}},
	} {
		t.Run(test.label, func(t *testing.T) {
			conf := &configuration.EnvironmentLocal{}
			require.NoError(t, conf.SetDefaults())
			conf.User.Name = template.MustNewString("fixture")
			users := &characterizationUsers{account: test.account}
			if test.account == nil {
				users.err = user.ErrNoSuchUser
			}
			var raw []byte
			if !test.empty {
				var err error
				raw, err = json.Marshal(localToken{User: test.stored})
				require.NoError(t, err)
			}
			actual, err := (&LocalRepository{conf: conf, userRepository: users}).IsSessionCompatibleWith(targetTestContext{ctx: t.Context()}, targetTestSession{raw: raw})
			require.NoError(t, err)
			require.Equal(t, test.compatible, actual)
		})
	}
}
