//go:build darwin

package environment

import (
	"context"
	"encoding/json"
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

func TestValidateUnixLoginShell(t *testing.T) {
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
			err := validateUnixLoginShell(test.shell, shells)
			if test.allowed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.True(t, errors.Permission.IsErr(err))
			}
		})
	}

	err := validateUnixLoginShell(executable, filepath.Join(directory, "missing-shells"))
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
	require.False(t, accepted)
	require.ErrorIs(t, err, user.ErrUserDoesNotFulfilRequirement)
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

func TestDarwinWillBeAcceptedExposesCanonicalTargetAccount(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.LoginAllowed = template.MustNewBool(`{{eq .targetAccount.name "alice"}}`)
	lookupCount := 0
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(_ context.Context, name string) (*user.User, error) {
			require.Equal(t, "alice", name)
			lookupCount++
			return newDarwinTargetAccountTestUser(), nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()

	accepted, err := repository.WillBeAccepted(request)
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, 1, lookupCount)
}

func TestDarwinTargetAccountDefaultsToRemoteSshUser(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.User.Name = template.String{}
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(_ context.Context, name string) (*user.User, error) {
			require.Equal(t, "source-user", name)
			target := newDarwinTargetAccountTestUser()
			target.Name = name
			return target, nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()

	accepted, err := repository.WillBeAccepted(request)
	require.NoError(t, err)
	require.True(t, accepted)
}

func TestDarwinTargetAccountSelection(t *testing.T) {
	uid := template.MustNewTextMarshaller[user.Id, *user.Id]("501")
	tests := map[string]struct {
		configure    func(*configuration.EnvironmentLocal)
		lookupByName func(context.Context, string) (*user.User, error)
		lookupById   func(context.Context, user.Id) (*user.User, error)
		wantError    bool
	}{
		"name": {
			lookupByName: func(_ context.Context, name string) (*user.User, error) {
				require.Equal(t, "alice", name)
				return newDarwinTargetAccountTestUser(), nil
			},
		},
		"UID only": {
			configure: func(conf *configuration.EnvironmentLocal) {
				conf.User.Name = template.String{}
				conf.User.Uid = &uid
			},
			lookupById: func(_ context.Context, id user.Id) (*user.User, error) {
				require.Equal(t, user.Id(501), id)
				return newDarwinTargetAccountTestUser(), nil
			},
		},
		"name takes priority and UID is a constraint": {
			configure: func(conf *configuration.EnvironmentLocal) {
				mismatchingUid := template.MustNewTextMarshaller[user.Id, *user.Id]("502")
				conf.User.Uid = &mismatchingUid
			},
			lookupByName: func(_ context.Context, name string) (*user.User, error) {
				require.Equal(t, "alice", name)
				return newDarwinTargetAccountTestUser(), nil
			},
			wantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			conf := newDarwinTargetAccountTestConfiguration(t)
			if test.configure != nil {
				test.configure(conf)
			}
			repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
			repository.conf = conf
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: test.lookupByName,
				lookupById:   test.lookupById,
			}
			request, closeRequest := newDarwinTargetAccountTestRequest(t)
			defer closeRequest()

			accepted, err := repository.WillBeAccepted(request)
			if test.wantError {
				require.False(t, accepted)
				require.ErrorIs(t, err, user.ErrUserDoesNotFulfilRequirement)
			} else {
				require.NoError(t, err)
				require.True(t, accepted)
			}
		})
	}
}

func TestDarwinTargetAccountChecksEveryRenderedRequirementField(t *testing.T) {
	uid := template.MustNewTextMarshaller[user.Id, *user.Id]("502")
	gid := template.MustNewTextMarshaller[user.GroupId, *user.GroupId]("21")
	tests := map[string]func(*configuration.UserRequirementTemplate){
		"display name": func(requirement *configuration.UserRequirementTemplate) {
			requirement.DisplayName = template.MustNewString("Mallory")
		},
		"UID": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Uid = &uid
		},
		"primary group name": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Group.Name = template.MustNewString("ops")
		},
		"primary group GID": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Group.Gid = &gid
		},
		"supplementary groups": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Groups = configuration.GroupRequirementTemplates{{Name: template.MustNewString("ops")}}
		},
		"shell": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Shell = template.MustNewString("/bin/bash")
		},
		"home directory": func(requirement *configuration.UserRequirementTemplate) {
			requirement.HomeDir = template.MustNewString("/Users/mallory")
		},
		"skeleton directory": func(requirement *configuration.UserRequirementTemplate) {
			requirement.Skel = template.MustNewString("/etc/skel")
		},
	}

	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			conf := newDarwinTargetAccountTestConfiguration(t)
			configure(&conf.User)
			repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
			repository.conf = conf
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: func(context.Context, string) (*user.User, error) {
					return newDarwinTargetAccountTestUser(), nil
				},
			}
			request, closeRequest := newDarwinTargetAccountTestRequest(t)
			defer closeRequest()

			accepted, err := repository.WillBeAccepted(request)
			require.False(t, accepted)
			require.ErrorIs(t, err, user.ErrUserDoesNotFulfilRequirement)
		})
	}
}

func TestDarwinTargetAccountSupplementaryGroupsAreAnExactUnorderedSet(t *testing.T) {
	group42 := user.GroupId(42)
	group12 := user.GroupId(12)
	requirement := user.Requirement{Groups: user.GroupRequirements{
		{Name: "everyone", Gid: &group12},
		{Name: "developers", Gid: &group42},
	}}
	target := newDarwinTargetAccountTestUser()
	require.NoError(t, userFulfilsRequirement(target, &requirement))

	requirement.Groups = requirement.Groups[:1]
	require.ErrorIs(t, userFulfilsRequirement(target, &requirement), user.ErrUserDoesNotFulfilRequirement)
	requirement.Groups = user.GroupRequirements{{Name: "developers"}, {Name: "ops"}}
	require.ErrorIs(t, userFulfilsRequirement(target, &requirement), user.ErrUserDoesNotFulfilRequirement)
}

func TestDarwinEnsureNeverMutatesUsers(t *testing.T) {
	for _, field := range []string{"create", "update"} {
		t.Run(field, func(t *testing.T) {
			conf := newDarwinTargetAccountTestConfiguration(t)
			if field == "create" {
				conf.CreateIfAbsent = template.MustNewBool("true")
			} else {
				conf.UpdateIfDifferent = template.MustNewBool("true")
			}
			ensureCalls := 0
			repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
			repository.conf = conf
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: func(context.Context, string) (*user.User, error) {
					return newDarwinTargetAccountTestUser(), nil
				},
				ensure: func(context.Context, *user.Requirement, *user.EnsureOpts) (*user.User, user.EnsureResult, error) {
					ensureCalls++
					return nil, user.EnsureResultError, stderrors.New("unexpected mutation")
				},
			}
			request, closeRequest := newDarwinTargetAccountTestRequest(t)
			defer closeRequest()
			request.authorization.(*sshTestAuthorization).kind = "simple"

			actual, err := repository.Ensure(request)
			require.NoError(t, err)
			require.NotNil(t, actual)
			require.Zero(t, ensureCalls)
		})
	}
}

func TestDarwinExistingEnvironmentMappingMismatchIsRejected(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.User.Name = template.MustNewString("bob")
	alice := newDarwinTargetAccountTestUser()
	bob := newDarwinTargetAccountTestUser()
	bob.Name = "bob"
	bob.Uid = 502
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(_ context.Context, name string) (*user.User, error) {
			if name == "alice" {
				return alice, nil
			}
			return bob, nil
		},
		lookupById: func(context.Context, user.Id) (*user.User, error) { return alice, nil },
	}
	stored, err := json.Marshal(localToken{
		User:              localTokenUser{Name: alice.Name, Uid: &alice.Uid},
		AuthorizationKind: "simple",
	})
	require.NoError(t, err)
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "simple"
	request.authorization.FindSession().(*sshTestStoredSession).environmentToken = stored

	actual, err := repository.Ensure(request)
	require.Nil(t, actual)
	require.ErrorIs(t, err, ErrNotAcceptable)
}

func TestDarwinNoneAuthorizationRequiresUnsafeOptIn(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "default denied", true: "explicitly allowed"}[allowed], func(t *testing.T) {
			conf := newDarwinTargetAccountTestConfiguration(t)
			conf.TargetAccountPolicy.AllowUnsafeNoneAuthorization = allowed
			repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
			repository.conf = conf
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: func(context.Context, string) (*user.User, error) {
					return newDarwinTargetAccountTestUser(), nil
				},
			}
			request, closeRequest := newDarwinTargetAccountTestRequest(t)
			defer closeRequest()
			request.authorization.(*sshTestAuthorization).kind = "none"

			accepted, err := repository.WillBeAccepted(request)
			require.NoError(t, err)
			require.Equal(t, allowed, accepted)
		})
	}
}

func TestDarwinEnsureExposesCanonicalTargetAccountToPolicyTemplates(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.PortForwardingAllowed = template.MustNewBool(`{{eq .targetAccount.uid 501}}`)
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) {
			return newDarwinTargetAccountTestUser(), nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization.(*sshTestAuthorization).kind = "simple"

	actual, err := repository.Ensure(request)
	require.NoError(t, err)
	require.True(t, actual.(*local).portForwardingAllowed)
	stored := request.authorization.FindSession().(*sshTestStoredSession)
	var token localToken
	require.NoError(t, json.Unmarshal(stored.environmentToken, &token))
	require.Equal(t, "alice", token.User.Name)
	require.NotNil(t, token.User.Uid)
	require.Equal(t, user.Id(501), *token.User.Uid)
	require.Equal(t, "simple", token.AuthorizationKind)
}

func TestDarwinLocalAuthorizationMustTargetAuthenticatedAccount(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) {
			return newDarwinTargetAccountTestUser(), nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()
	authenticated := newDarwinTargetAccountTestUser()
	request.authorization = &darwinLocalTestAuthorization{sshTestAuthorization: request.authorization.(*sshTestAuthorization), user: authenticated}

	accepted, err := repository.WillBeAccepted(request)
	require.NoError(t, err)
	require.True(t, accepted)

	authenticated.Uid++
	accepted, err = repository.WillBeAccepted(request)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestDarwinEnsureRechecksLocalAuthorizationTargetBinding(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	lookupCount := 0
	repository := newDarwinTargetAccountTestRepository(conf.TargetAccountPolicy)
	repository.conf = conf
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupByName: func(context.Context, string) (*user.User, error) {
			lookupCount++
			target := newDarwinTargetAccountTestUser()
			if lookupCount > 1 {
				target.Name = "bob"
				target.Uid = 502
			}
			return target, nil
		},
	}
	request, closeRequest := newDarwinTargetAccountTestRequest(t)
	defer closeRequest()
	request.authorization = &darwinLocalTestAuthorization{
		sshTestAuthorization: request.authorization.(*sshTestAuthorization),
		user:                 newDarwinTargetAccountTestUser(),
	}

	actual, err := repository.Ensure(request)
	require.Nil(t, actual)
	require.ErrorIs(t, err, user.ErrUserDoesNotFulfilRequirement)
	require.Equal(t, 2, lookupCount)
}

func TestDarwinEnsureRechecksResolvedTargetForNoneLikeAuthorization(t *testing.T) {
	conf := newDarwinTargetAccountTestConfiguration(t)
	conf.TargetAccountPolicy.AllowUnsafeNoneAuthorization = true
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

func TestDarwinEnvironmentRestoreAppliesCurrentNonePolicy(t *testing.T) {
	target := newDarwinTargetAccountTestUser()
	token, err := json.Marshal(localToken{
		User:              localTokenUser{Name: target.Name, Uid: &target.Uid},
		AuthorizationKind: "none",
	})
	require.NoError(t, err)
	sess := &sshTestStoredSession{id: session.MustNewId(), environmentToken: token}

	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[allowed], func(t *testing.T) {
			repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{
				AllowUnsafeNoneAuthorization: allowed,
			})
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: func(context.Context, string) (*user.User, error) { return target, nil },
				lookupById:   func(context.Context, user.Id) (*user.User, error) { return target, nil },
			}

			actual, err := repository.FindBySession(context.Background(), sess, nil)
			if allowed {
				require.NoError(t, err)
				require.NotNil(t, actual)
			} else {
				require.ErrorIs(t, err, ErrNotAcceptable)
				require.Nil(t, actual)
			}
		})
	}
}

func TestDarwinStoredTargetAccountRequiresMatchingNameAndUid(t *testing.T) {
	repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})
	target := newDarwinTargetAccountTestUser()
	repository.userRepository = &darwinTargetAccountTestUserRepository{
		lookupById: func(context.Context, user.Id) (*user.User, error) { return target, nil },
	}
	token := &localToken{User: localTokenUser{Name: target.Name, Uid: &target.Uid}, AuthorizationKind: "simple"}

	accepted, err := repository.isStoredTargetAccountAccepted(context.Background(), target, token)
	require.NoError(t, err)
	require.True(t, accepted)

	token.User.Name = "bob"
	accepted, err = repository.isStoredTargetAccountAccepted(context.Background(), target, token)
	require.NoError(t, err)
	require.False(t, accepted)

	token.User.Name = target.Name
	otherUid := user.Id(502)
	token.User.Uid = &otherUid
	accepted, err = repository.isStoredTargetAccountAccepted(context.Background(), target, token)
	require.NoError(t, err)
	require.False(t, accepted)
}

func TestDarwinEnvironmentRestoreRejectsChangedOrIncompleteIdentity(t *testing.T) {
	uid := user.Id(501)
	tests := map[string]struct {
		token        localTokenUser
		lookupByName func(context.Context, string) (*user.User, error)
		lookupById   func(context.Context, user.Id) (*user.User, error)
	}{
		"missing name": {
			token: localTokenUser{Uid: &uid},
			lookupById: func(context.Context, user.Id) (*user.User, error) {
				return newDarwinTargetAccountTestUser(), nil
			},
		},
		"missing UID": {
			token: localTokenUser{Name: "alice"},
			lookupByName: func(context.Context, string) (*user.User, error) {
				return newDarwinTargetAccountTestUser(), nil
			},
		},
		"name reused": {
			token: localTokenUser{Name: "alice", Uid: &uid},
			lookupByName: func(context.Context, string) (*user.User, error) {
				target := newDarwinTargetAccountTestUser()
				target.Uid = 502
				return target, nil
			},
		},
		"UID remapped": {
			token: localTokenUser{Name: "alice", Uid: &uid},
			lookupByName: func(context.Context, string) (*user.User, error) {
				return newDarwinTargetAccountTestUser(), nil
			},
			lookupById: func(context.Context, user.Id) (*user.User, error) {
				target := newDarwinTargetAccountTestUser()
				target.Name = "bob"
				return target, nil
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			repository := newDarwinTargetAccountTestRepository(configuration.EnvironmentLocalTargetAccountPolicy{})
			repository.userRepository = &darwinTargetAccountTestUserRepository{
				lookupByName: test.lookupByName,
				lookupById:   test.lookupById,
			}
			token, err := json.Marshal(localToken{User: test.token, AuthorizationKind: "simple"})
			require.NoError(t, err)
			sess := &sshTestStoredSession{id: session.MustNewId(), environmentToken: token}

			actual, err := repository.FindBySession(context.Background(), sess, nil)
			require.Nil(t, actual)
			require.Error(t, err)
		})
	}
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
	ensure       func(context.Context, *user.Requirement, *user.EnsureOpts) (*user.User, user.EnsureResult, error)
}

type darwinLocalTestAuthorization struct {
	*sshTestAuthorization
	user *user.User
}

func (*darwinLocalTestAuthorization) AuthorizationKind() string  { return "local" }
func (this *darwinLocalTestAuthorization) LocalUser() *user.User { return this.user }

func (this *darwinTargetAccountTestUserRepository) LookupByName(ctx context.Context, name string) (*user.User, error) {
	if this.lookupByName == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.lookupByName(ctx, name)
}

func (this *darwinTargetAccountTestUserRepository) LookupById(ctx context.Context, id user.Id) (*user.User, error) {
	if this.lookupById == nil {
		return nil, user.ErrNoSuchUser
	}
	return this.lookupById(ctx, id)
}

func (this *darwinTargetAccountTestUserRepository) Ensure(ctx context.Context, requirement *user.Requirement, opts *user.EnsureOpts) (*user.User, user.EnsureResult, error) {
	if this.ensure == nil {
		return nil, user.EnsureResultError, stderrors.New("unexpected Ensure call")
	}
	return this.ensure(ctx, requirement, opts)
}

func newDarwinTargetAccountTestUser() *user.User {
	return &user.User{
		Name:        "alice",
		DisplayName: "Alice",
		Uid:         501,
		Group:       user.Group{Gid: 20, Name: "staff"},
		Groups:      user.Groups{{Gid: 42, Name: "developers"}, {Gid: 12, Name: "everyone"}},
		Shell:       "/bin/zsh",
		HomeDir:     "/Users/alice",
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
