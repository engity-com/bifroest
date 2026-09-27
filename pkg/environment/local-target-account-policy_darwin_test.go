//go:build darwin

package environment

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestDarwinTargetAccountPolicyDefaultDenials(t *testing.T) {
	tests := map[string]func(*user.User){
		"UID zero": func(target *user.User) {
			target.Uid = 0
		},
		"system account": func(target *user.User) {
			target.Name = "_daemon"
		},
		"primary admin group": func(target *user.User) {
			target.Group = user.Group{Gid: 80, Name: "admin"}
		},
		"supplementary admin group": func(target *user.User) {
			target.Groups = append(target.Groups, user.Group{Gid: 80, Name: "admin"})
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			target := newDarwinTargetAccountTestUser()
			mutate(target)
			repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})

			accepted, err := repository.isTargetAccountAccepted(target)
			require.NoError(t, err)
			require.False(t, accepted)
		})
	}

	repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})
	accepted, err := repository.isTargetAccountAccepted(newDarwinTargetAccountTestUser())
	require.NoError(t, err)
	require.True(t, accepted)
}

func TestDarwinTargetAccountPolicyDefaultOverrides(t *testing.T) {
	tests := map[string]struct {
		policy configuration.EnvironmentLocalTargetAccountPolicy
		mutate func(*user.User)
	}{
		"UID zero": {
			policy: configuration.EnvironmentLocalTargetAccountPolicy{AllowUidZero: true},
			mutate: func(target *user.User) { target.Uid = 0 },
		},
		"system account": {
			policy: configuration.EnvironmentLocalTargetAccountPolicy{AllowSystemAccounts: true},
			mutate: func(target *user.User) { target.Name = "_service" },
		},
		"primary admin group": {
			policy: configuration.EnvironmentLocalTargetAccountPolicy{AllowAdministrators: true},
			mutate: func(target *user.User) { target.Group = user.Group{Gid: 80, Name: "admin"} },
		},
		"supplementary admin group": {
			policy: configuration.EnvironmentLocalTargetAccountPolicy{AllowAdministrators: true},
			mutate: func(target *user.User) {
				target.Groups = append(target.Groups, user.Group{Gid: 80, Name: "admin"})
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			target := newDarwinTargetAccountTestUser()
			test.mutate(target)
			repository := newDarwinTargetAccountTestRepository(test.policy)

			accepted, err := repository.isTargetAccountAccepted(target)
			require.NoError(t, err)
			require.True(t, accepted)
		})
	}
}

func TestDarwinTargetAccountPolicyAllowlistsMustAllMatch(t *testing.T) {
	policy := configuration.EnvironmentLocalTargetAccountPolicy{
		AllowedNames:  []string{"alice"},
		AllowedUids:   []user.Id{501},
		AllowedGroups: []string{"developers"},
		AllowedGids:   []user.GroupId{20},
	}
	repository := newDarwinTargetAccountTestRepository(policy)
	target := newDarwinTargetAccountTestUser()

	accepted, err := repository.isTargetAccountAccepted(target)
	require.NoError(t, err)
	require.True(t, accepted)

	for name, mutate := range map[string]func(*configuration.EnvironmentLocalTargetAccountPolicy){
		"name": func(policy *configuration.EnvironmentLocalTargetAccountPolicy) { policy.AllowedNames = []string{"bob"} },
		"UID":  func(policy *configuration.EnvironmentLocalTargetAccountPolicy) { policy.AllowedUids = []user.Id{502} },
		"group": func(policy *configuration.EnvironmentLocalTargetAccountPolicy) {
			policy.AllowedGroups = []string{"ops"}
		},
		"GID": func(policy *configuration.EnvironmentLocalTargetAccountPolicy) {
			policy.AllowedGids = []user.GroupId{21}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := policy
			mutate(&candidate)
			repository := newDarwinTargetAccountTestRepository(candidate)
			accepted, err := repository.isTargetAccountAccepted(target)
			require.NoError(t, err)
			require.False(t, accepted)
		})
	}
}

func TestDarwinTargetAccountPolicyDenylistsWin(t *testing.T) {
	tests := map[string]configuration.EnvironmentLocalTargetAccountPolicy{
		"name": {
			AllowedNames: []string{"alice"}, DeniedNames: []string{"alice"},
		},
		"UID including override": {
			AllowUidZero: true, AllowedUids: []user.Id{0}, DeniedUids: []user.Id{0},
		},
		"primary group": {
			AllowedGroups: []string{"staff"}, DeniedGroups: []string{"staff"},
		},
		"supplementary GID": {
			AllowedGids: []user.GroupId{42}, DeniedGids: []user.GroupId{42},
		},
	}

	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			target := newDarwinTargetAccountTestUser()
			if name == "UID including override" {
				target.Uid = 0
			}
			repository := newDarwinTargetAccountTestRepository(policy)
			accepted, err := repository.isTargetAccountAccepted(target)
			require.NoError(t, err)
			require.False(t, accepted)
		})
	}
}

func TestValidateDarwinLoginShell(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "zsh")
	unlisted := filepath.Join(directory, "custom-shell")
	nonExecutable := filepath.Join(directory, "not-executable")
	falseShell := filepath.Join(directory, "false")
	nologinShell := filepath.Join(directory, "nologin")
	for _, path := range []string{executable, unlisted, falseShell, nologinShell} {
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0755))
	}
	require.NoError(t, os.WriteFile(nonExecutable, []byte("#!/bin/sh\n"), 0644))
	shells := filepath.Join(directory, "shells")
	require.NoError(t, os.WriteFile(shells, []byte("# allowed shells\n  "+executable+"  # default\n"), 0644))

	tests := map[string]struct {
		shell   string
		allowed bool
	}{
		"listed executable": {shell: executable, allowed: true},
		"empty":             {shell: ""},
		"false":             {shell: falseShell},
		"nologin":           {shell: nologinShell},
		"relative":          {shell: "bin/zsh"},
		"directory":         {shell: directory},
		"not executable":    {shell: nonExecutable},
		"not listed":        {shell: unlisted},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateDarwinLoginShell(test.shell, shells)
			if test.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.True(t, errors.Permission.IsErr(err))
			}
		})
	}

	err := validateDarwinLoginShell(executable, filepath.Join(directory, "missing-shells"))
	require.Error(t, err)
	require.True(t, errors.System.IsErr(err))
}

func TestDarwinTargetAccountPolicyNonLoginShellOverride(t *testing.T) {
	repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{AllowNonLoginShell: true})
	repository.targetAccountShellValidator = func(string) error {
		return stderrors.New("must not be called")
	}
	target := newDarwinTargetAccountTestUser()
	target.Shell = ""

	accepted, err := repository.isTargetAccountAccepted(target)
	require.NoError(t, err)
	require.True(t, accepted)
}

func TestDarwinWillBeAcceptedChecksRenderedCanonicalTarget(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.User.Name = template.MustNewString("alias")
	lookedUp := false
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(_ context.Context, name string) (*user.User, error) {
			require.Equal(t, "alias", name)
			lookedUp = true
			target := newDarwinTargetAccountTestUser()
			target.Name = "_canonical"
			return target, nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()

	accepted, err := repository.WillBeAccepted(request)
	require.NoError(t, err)
	require.False(t, accepted)
	require.True(t, lookedUp)
}

func TestDarwinWillBeAcceptedFailsClosedOnLookupError(t *testing.T) {
	expected := stderrors.New("directory service unavailable")
	conf := newDarwinTargetAccountTestConfiguration(t)
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) { return nil, expected },
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()

	accepted, err := repository.WillBeAccepted(request)
	require.False(t, accepted)
	require.ErrorIs(t, err, expected)
}

func TestDarwinEnsureRechecksResolvedTargetForNoneLikeAuthorization(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	lookupCount := 0
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) {
			lookupCount++
			target := newDarwinTargetAccountTestUser()
			if lookupCount > 1 {
				target.Uid = 0
			}
			return target, nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "none"

	actual, err := repository.Ensure(request)
	require.Nil(t, actual)
	require.ErrorIs(t, err, ErrNotAcceptable)
	require.Equal(t, 2, lookupCount)
}

func TestDarwinStoredTargetAccountRequiresMatchingNameAndUid(t *testing.T) {
	repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})
	target := newDarwinTargetAccountTestUser()
	token := &localToken{User: localTokenUser{Name: target.Name, Uid: &target.Uid}}

	accepted, err := repository.isStoredTargetAccountAccepted(target, token)
	require.NoError(t, err)
	require.True(t, accepted)

	token.User.Name = "bob"
	accepted, err = repository.isStoredTargetAccountAccepted(target, token)
	require.NoError(t, err)
	require.False(t, accepted)

	token.User.Name = target.Name
	otherUid := user.Id(502)
	token.User.Uid = &otherUid
	accepted, err = repository.isStoredTargetAccountAccepted(target, token)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestDarwinTargetAccountPreStartRevalidation(t *testing.T) {
	tests := map[string]struct {
		mutateByName func(*user.User)
		mutateByUid  func(*user.User)
		policy       configuration.EnvironmentLocalTargetAccountPolicy
		wantError    bool
	}{
		"unchanged": {},
		"supplementary group order is not significant": {
			mutateByName: reverseDarwinTargetAccountTestGroups,
			mutateByUid:  reverseDarwinTargetAccountTestGroups,
		},
		"name lookup UID changed": {
			mutateByName: func(target *user.User) { target.Uid++ }, wantError: true,
		},
		"UID lookup name changed": {
			mutateByUid: func(target *user.User) { target.Name = "bob" }, wantError: true,
		},
		"security snapshot changed": {
			mutateByName: func(target *user.User) { target.Shell = "/bin/bash" }, wantError: true,
		},
		"current policy denies": {
			policy: configuration.EnvironmentLocalTargetAccountPolicy{DeniedNames: []string{"alice"}}, wantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			expected := newDarwinTargetAccountTestUser()
			repository := newDarwinTargetAccountTestRepository(test.policy)
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: func(context.Context, string) (*user.User, error) {
					actual, err := expected.Clone()
					require.NoError(t, err)
					if test.mutateByName != nil {
						test.mutateByName(actual)
					}
					return actual, nil
				},
				lookupById: func(context.Context, user.Id) (*user.User, error) {
					actual, err := expected.Clone()
					require.NoError(t, err)
					if test.mutateByUid != nil {
						test.mutateByUid(actual)
					}
					return actual, nil
				},
			}
			environment := &local{repository: repository, user: expected}

			err := environment.revalidateTargetAccount(context.Background())
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDarwinTargetAccountPreStartLookupFailureIsClosed(t *testing.T) {
	expected := stderrors.New("directory service unavailable")
	repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) { return nil, expected },
	}
	environment := &local{repository: repository, user: newDarwinTargetAccountTestUser()}

	err := environment.revalidateTargetAccount(context.Background())
	require.ErrorIs(t, err, expected)
}

type darwinTargetAccountTestUserRepository struct {
	user.CloseableRepository
	lookupByName func(context.Context, string) (*user.User, error)
	lookupById   func(context.Context, user.Id) (*user.User, error)
}

func (this *darwinTargetAccountTestUserRepository) LookupByName(ctx context.Context, name string) (*user.User, error) {
	return this.lookupByName(ctx, name)
}

func (this *darwinTargetAccountTestUserRepository) LookupById(ctx context.Context, id user.Id) (*user.User, error) {
	return this.lookupById(ctx, id)
}

func newDarwinTargetAccountTestUser() *user.User {
	return &user.User{
		Name:    "alice",
		Uid:     501,
		Group:   user.Group{Gid: 20, Name: "staff"},
		Groups:  user.Groups{{Gid: 42, Name: "developers"}, {Gid: 12, Name: "everyone"}},
		Shell:   "/bin/zsh",
		HomeDir: "/Users/alice",
	}
}

func newDarwinTargetAccountTestRepository(policy configuration.EnvironmentLocalTargetAccountPolicy) *LocalRepository {
	return &LocalRepository{
		conf: &configuration.EnvironmentLocal{
			EnvironmentLocalPlatform: configuration.EnvironmentLocalPlatform{TargetAccountPolicy: policy},
		},
		targetAccountShellValidator: func(string) error { return nil },
	}
}

func newDarwinTargetAccountTestConfiguration(t *testing.T) *configuration.EnvironmentLocal {
	t.Helper()
	conf := &configuration.EnvironmentLocal{}
	require.NoError(t, conf.SetDefaults())
	conf.User.Name = template.MustNewString("alice")
	return conf
}

func newDarwinTargetAccountTestRequest(t *testing.T) (*sshTestTask, context.CancelFunc) {
	t.Helper()
	ctx, cancel := newSshTestContext()
	storedSession := &sshTestStoredSession{id: session.MustNewId()}
	return &sshTestTask{
		context:       ctx,
		connection:    &sshTestConnection{id: connection.MustNewId(), context: ctx},
		authorization: &sshTestAuthorization{session: storedSession},
	}, cancel
}

func reverseDarwinTargetAccountTestGroups(target *user.User) {
	for left, right := 0, len(target.Groups)-1; left < right; left, right = left+1, right-1 {
		target.Groups[left], target.Groups[right] = target.Groups[right], target.Groups[left]
	}
}
