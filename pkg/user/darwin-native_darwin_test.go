//go:build darwin

package user

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	osuser "os/user"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/process"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/stretchr/testify/require"
)

type fakeDarwinUser struct {
	name, displayName, shell, home, generatedUID string
	uid                                          Id
	gid                                          GroupId
}

type fakeDarwinGroup struct {
	name         string
	gid          GroupId
	members      map[string]bool
	memberUIDs   map[string]bool
	generatedUID string
}

type fakeDarwinRunner struct {
	mutex       sync.Mutex
	users       map[string]*fakeDarwinUser
	groups      map[string]*fakeDarwinGroup
	calls       []string
	mutationCnt int
}

type failingDarwinRunner struct {
	delegate darwinCommandRunner
	fail     func(string, []string) bool
	failed   bool
}

func (this *failingDarwinRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if !this.failed && this.fail(path, args) {
		this.failed = true
		return nil, errors.New("injected Darwin command failure")
	}
	return this.delegate.Run(ctx, path, args...)
}

func newFakeDarwinRunner() *fakeDarwinRunner {
	return &fakeDarwinRunner{users: map[string]*fakeDarwinUser{}, groups: map[string]*fakeDarwinGroup{}}
}

func (this *fakeDarwinRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.calls = append(this.calls, path+" "+strings.Join(args, " "))
	if path != darwinDSCLPath && path != darwinDSEditGroupPath {
		return nil, fmt.Errorf("unexpected executable %q", path)
	}
	if path == darwinDSEditGroupPath {
		return this.editGroup(args)
	}
	if len(args) >= 4 && args[0] == "-url" && args[1] == darwinLocalNode && args[2] == "-read" {
		return this.read(args[3])
	}
	if len(args) >= 4 && args[0] == "-url" && args[1] == darwinLocalNode && args[2] == "-readall" {
		return this.readAll(args[3])
	}
	if len(args) < 3 || args[0] != darwinLocalNode {
		return nil, fmt.Errorf("unexpected dscl arguments: %v", args)
	}
	switch args[1] {
	case "-create":
		return this.create(args[2:])
	case "-merge":
		return this.merge(args[2:])
	case "-change":
		return this.change(args[2:])
	case "-delete":
		return this.delete(args[2:])
	default:
		return nil, fmt.Errorf("unexpected dscl operation: %v", args)
	}
}

func (this *fakeDarwinRunner) merge(args []string) ([]byte, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("unexpected merge: %v", args)
	}
	kind, name, ok := strings.Cut(strings.TrimPrefix(args[0], "/"), "/")
	if !ok || kind != "Groups" || this.groups[name] == nil {
		return fakeDarwinMissing()
	}
	this.mutationCnt++
	group := this.groups[name]
	switch args[1] {
	case "GroupMembership":
		if group.members == nil {
			group.members = map[string]bool{}
		}
		group.members[args[2]] = true
	case "GroupMembers":
		if group.memberUIDs == nil {
			group.memberUIDs = map[string]bool{}
		}
		group.memberUIDs[args[2]] = true
	default:
		return nil, fmt.Errorf("unexpected merge attribute %q", args[1])
	}
	return nil, nil
}

func fakeDarwinMissing() ([]byte, error) {
	return []byte("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"), errors.New("exit status 255")
}

func fakeDarwinEncode(value string) string {
	return url.PathEscape(value)
}

func (this *fakeDarwinRunner) read(path string) ([]byte, error) {
	kind, name, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !ok {
		return nil, fmt.Errorf("invalid record path %q", path)
	}
	switch kind {
	case "Users":
		candidate := this.users[name]
		if candidate == nil {
			return fakeDarwinMissing()
		}
		return []byte(this.userRecord(candidate)), nil
	case "Groups":
		candidate := this.groups[name]
		if candidate == nil {
			return fakeDarwinMissing()
		}
		return []byte(this.groupRecord(candidate)), nil
	default:
		return nil, fmt.Errorf("unexpected record kind %q", kind)
	}
}

func (this *fakeDarwinRunner) readAll(path string) ([]byte, error) {
	var records []string
	switch path {
	case "/Users":
		names := make([]string, 0, len(this.users))
		for name := range this.users {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			records = append(records, this.userRecord(this.users[name]))
		}
	case "/Groups":
		names := make([]string, 0, len(this.groups))
		for name := range this.groups {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			records = append(records, this.groupRecord(this.groups[name]))
		}
	default:
		return nil, fmt.Errorf("unexpected readall path %q", path)
	}
	return []byte(strings.Join(records, "-\n")), nil
}

func (this *fakeDarwinRunner) userRecord(candidate *fakeDarwinUser) string {
	result := fmt.Sprintf("RecordName: %s\nUniqueID: %d\nPrimaryGroupID: %d\nRealName: %s\nUserShell: %s\nNFSHomeDirectory: %s\n",
		fakeDarwinEncode(candidate.name), candidate.uid, candidate.gid, fakeDarwinEncode(candidate.displayName),
		fakeDarwinEncode(candidate.shell), fakeDarwinEncode(candidate.home))
	if candidate.generatedUID != "" {
		result += "GeneratedUID: " + fakeDarwinEncode(candidate.generatedUID) + "\n"
	}
	return result
}

func (this *fakeDarwinRunner) groupRecord(candidate *fakeDarwinGroup) string {
	members := make([]string, 0, len(candidate.members))
	for member := range candidate.members {
		members = append(members, fakeDarwinEncode(member))
	}
	sort.Strings(members)
	result := fmt.Sprintf("RecordName: %s\nPrimaryGroupID: %d\n", fakeDarwinEncode(candidate.name), candidate.gid)
	if len(members) > 0 {
		result += "GroupMembership: " + strings.Join(members, " ") + "\n"
	}
	memberUIDs := make([]string, 0, len(candidate.memberUIDs))
	for memberUID := range candidate.memberUIDs {
		memberUIDs = append(memberUIDs, fakeDarwinEncode(memberUID))
	}
	sort.Strings(memberUIDs)
	if len(memberUIDs) > 0 {
		result += "GroupMembers: " + strings.Join(memberUIDs, " ") + "\n"
	}
	if candidate.generatedUID != "" {
		result += "GeneratedUID: " + fakeDarwinEncode(candidate.generatedUID) + "\n"
	}
	return result
}

func (this *fakeDarwinRunner) create(args []string) ([]byte, error) {
	kind, name, ok := strings.Cut(strings.TrimPrefix(args[0], "/"), "/")
	if !ok {
		return nil, fmt.Errorf("invalid create path")
	}
	this.mutationCnt++
	switch kind {
	case "Users":
		candidate := this.users[name]
		if candidate == nil {
			candidate = &fakeDarwinUser{name: name}
			this.users[name] = candidate
		}
		if len(args) == 3 {
			value := args[2]
			switch args[1] {
			case "UniqueID":
				_, _ = fmt.Sscan(value, &candidate.uid)
			case "PrimaryGroupID":
				_, _ = fmt.Sscan(value, &candidate.gid)
			case "RealName":
				candidate.displayName = value
			case "UserShell":
				candidate.shell = value
			case "NFSHomeDirectory":
				candidate.home = value
			case "GeneratedUID":
				candidate.generatedUID = value
			}
		}
	case "Groups":
		candidate := this.groups[name]
		if candidate == nil {
			candidate = &fakeDarwinGroup{name: name, members: map[string]bool{}}
			this.groups[name] = candidate
		}
		if len(args) >= 3 {
			switch args[1] {
			case "PrimaryGroupID":
				_, _ = fmt.Sscan(args[2], &candidate.gid)
			case "GroupMembership":
				candidate.members = map[string]bool{}
				for _, member := range args[2:] {
					candidate.members[member] = true
				}
			case "GroupMembers":
				candidate.memberUIDs = map[string]bool{}
				for _, memberUID := range args[2:] {
					candidate.memberUIDs[memberUID] = true
				}
			case "GeneratedUID":
				candidate.generatedUID = args[2]
			}
		}
	default:
		return nil, fmt.Errorf("unexpected create kind")
	}
	return nil, nil
}

func (this *fakeDarwinRunner) change(args []string) ([]byte, error) {
	if len(args) != 4 || args[1] != "RecordName" {
		return nil, fmt.Errorf("unexpected change: %v", args)
	}
	this.mutationCnt++
	kind := strings.Split(strings.TrimPrefix(args[0], "/"), "/")[0]
	oldName, newName := args[2], args[3]
	if kind == "Users" {
		candidate := this.users[oldName]
		delete(this.users, oldName)
		candidate.name = newName
		this.users[newName] = candidate
	} else {
		candidate := this.groups[oldName]
		delete(this.groups, oldName)
		candidate.name = newName
		this.groups[newName] = candidate
	}
	return nil, nil
}

func (this *fakeDarwinRunner) delete(args []string) ([]byte, error) {
	kind, name, ok := strings.Cut(strings.TrimPrefix(args[0], "/"), "/")
	if !ok {
		return nil, fmt.Errorf("invalid delete path")
	}
	this.mutationCnt++
	if len(args) > 1 {
		if kind == "Users" {
			candidate := this.users[name]
			switch args[1] {
			case "RealName":
				candidate.displayName = ""
			case "UserShell":
				candidate.shell = ""
			case "NFSHomeDirectory":
				candidate.home = ""
			case "GeneratedUID":
				candidate.generatedUID = ""
			}
		} else {
			candidate := this.groups[name]
			if candidate == nil {
				return fakeDarwinMissing()
			}
			switch args[1] {
			case "GroupMembership":
				if len(args) == 3 {
					delete(candidate.members, args[2])
				} else {
					candidate.members = map[string]bool{}
				}
			case "GroupMembers":
				if len(args) == 3 {
					delete(candidate.memberUIDs, args[2])
				} else {
					candidate.memberUIDs = map[string]bool{}
				}
			case "GeneratedUID":
				candidate.generatedUID = ""
			}
		}
		return nil, nil
	}
	if kind == "Users" {
		if this.users[name] == nil {
			return fakeDarwinMissing()
		}
		delete(this.users, name)
	} else {
		if this.groups[name] == nil {
			return fakeDarwinMissing()
		}
		delete(this.groups, name)
	}
	return nil, nil
}

func (this *fakeDarwinRunner) editGroup(args []string) ([]byte, error) {
	if len(args) != 9 || args[0] != "-o" || args[1] != "edit" || args[2] != "-n" || args[3] != darwinLocalNode || args[6] != "-t" || args[7] != "user" {
		return nil, fmt.Errorf("unexpected dseditgroup arguments: %v", args)
	}
	group := this.groups[args[8]]
	if group == nil {
		return fakeDarwinMissing()
	}
	this.mutationCnt++
	if group.members == nil {
		group.members = map[string]bool{}
	}
	if group.memberUIDs == nil {
		group.memberUIDs = map[string]bool{}
	}
	member := this.users[args[5]]
	switch args[4] {
	case "-a":
		group.members[args[5]] = true
		if member != nil && member.generatedUID != "" {
			group.memberUIDs[member.generatedUID] = true
		}
	case "-d":
		delete(group.members, args[5])
		if member != nil && member.generatedUID != "" {
			delete(group.memberUIDs, member.generatedUID)
		}
	default:
		return nil, fmt.Errorf("unexpected member operation")
	}
	return nil, nil
}

func newFakeNativeDarwinRepository(runner darwinCommandRunner) *DarwinRepository {
	repository := &DarwinRepository{
		commandRunner: runner,
		lookupUserByName: func(name string) (*osuser.User, error) {
			return nil, osuser.UnknownUserError(name)
		},
		lookupUserById: func(id string) (*osuser.User, error) {
			return nil, osuser.UnknownUserError(id)
		},
		lookupGroupByName: func(name string) (*osuser.Group, error) {
			return nil, osuser.UnknownGroupError(name)
		},
		lookupGroupById: func(id string) (*osuser.Group, error) {
			return nil, osuser.UnknownGroupError(id)
		},
	}
	if fake, ok := runner.(*fakeDarwinRunner); ok {
		repository.lookupUserByName = func(name string) (*osuser.User, error) {
			fake.mutex.Lock()
			defer fake.mutex.Unlock()
			candidate := fake.users[name]
			if candidate == nil {
				return nil, osuser.UnknownUserError(name)
			}
			return &osuser.User{Username: candidate.name, Uid: candidate.uid.String(), Gid: candidate.gid.String(), HomeDir: candidate.home, Name: candidate.displayName}, nil
		}
		repository.lookupUserById = func(id string) (*osuser.User, error) {
			fake.mutex.Lock()
			defer fake.mutex.Unlock()
			for _, candidate := range fake.users {
				if candidate.uid.String() == id {
					return &osuser.User{Username: candidate.name, Uid: candidate.uid.String(), Gid: candidate.gid.String(), HomeDir: candidate.home, Name: candidate.displayName}, nil
				}
			}
			return nil, osuser.UnknownUserError(id)
		}
		repository.lookupGroupByName = func(name string) (*osuser.Group, error) {
			fake.mutex.Lock()
			defer fake.mutex.Unlock()
			candidate := fake.groups[name]
			if candidate == nil {
				return nil, osuser.UnknownGroupError(name)
			}
			return &osuser.Group{Name: candidate.name, Gid: candidate.gid.String()}, nil
		}
		repository.lookupGroupById = func(id string) (*osuser.Group, error) {
			fake.mutex.Lock()
			defer fake.mutex.Unlock()
			for _, candidate := range fake.groups {
				if candidate.gid.String() == id {
					return &osuser.Group{Name: candidate.name, Gid: candidate.gid.String()}, nil
				}
			}
			return nil, osuser.UnknownGroupIdError(id)
		}
	}
	return repository
}

func TestParseDarwinAttributesHandlesNativeMultilineValuesAndAliases(t *testing.T) {
	attrs := parseDarwinAttributes([]byte("RealName:\n Alice%20Example\nRecordName: alice alias\nUniqueID: 501\nPrimaryGroupID: 20\n"))
	record, err := darwinUserRecordFromAttributes(attrs)
	require.NoError(t, err)
	require.Equal(t, "alice", record.name)
	require.Equal(t, "Alice Example", record.displayName)
	require.Equal(t, Id(501), record.uid)
	require.Equal(t, GroupId(20), record.gid)
}

func TestParseDarwinIdAcceptsNativeNegativeSentinels(t *testing.T) {
	id, err := parseDarwinId("-2", "user")
	require.NoError(t, err)
	require.Equal(t, uint32(0xfffffffe), id)

	id, err = parseDarwinId("-1", "group")
	require.NoError(t, err)
	require.Equal(t, uint32(0xffffffff), id)
}

func TestDarwinRequirementDefaultsUseLoginShell(t *testing.T) {
	requirement := darwinRequirementDefaults(&Requirement{Name: "alice"})
	require.Equal(t, "/bin/sh", requirement.Shell)
}

func TestDarwinLocalIDLookupRejectsDuplicates(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501}
	runner.users["bob"] = &fakeDarwinUser{name: "bob", uid: 501}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	runner.groups["other"] = &fakeDarwinGroup{name: "other", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)

	actualUser, err := repository.localUserByID(t.Context(), 501)
	require.Nil(t, actualUser)
	require.ErrorContains(t, err, "multiple local users")
	actualGroup, err := repository.localGroupByID(t.Context(), 20)
	require.Nil(t, actualGroup)
	require.ErrorContains(t, err, "multiple local groups")
}

func TestDarwinEnsureGroupCreateUpdateAndUnchanged(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.groups["existing"] = &fakeDarwinGroup{name: "existing", gid: 1001, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)

	group, result, err := repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "developers"}, nil)
	require.NoError(t, err)
	require.Equal(t, EnsureResultCreated, result)
	require.Equal(t, &Group{Name: "developers", Gid: 1002}, group)

	group, result, err = repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "developers"}, nil)
	require.NoError(t, err)
	require.Equal(t, EnsureResultUnchanged, result)
	require.Equal(t, GroupId(1002), group.Gid)

	newGID := GroupId(1200)
	group, result, err = repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "developers", Gid: &newGID}, nil)
	require.NoError(t, err)
	require.Equal(t, EnsureResultModified, result)
	require.Equal(t, newGID, group.Gid)
	for _, call := range runner.calls {
		require.True(t, strings.HasPrefix(call, darwinDSCLPath+" ") || strings.HasPrefix(call, darwinDSEditGroupPath+" "), call)
		require.Contains(t, call, darwinLocalNode)
	}
}

func TestDarwinEnsureGroupHonorsMutationOptions(t *testing.T) {
	runner := newFakeDarwinRunner()
	repository := newFakeNativeDarwinRepository(runner)
	createDenied := false
	_, result, err := repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "missing"}, &EnsureOpts{CreateAllowed: &createDenied})
	require.ErrorIs(t, err, ErrNoSuchGroup)
	require.Equal(t, EnsureResultError, result)
	require.Zero(t, runner.mutationCnt)

	runner.groups["existing"] = &fakeDarwinGroup{name: "existing", gid: 1001, members: map[string]bool{}}
	modifyDenied := false
	newGID := GroupId(1002)
	_, result, err = repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "existing", Gid: &newGID}, &EnsureOpts{ModifyAllowed: &modifyDenied})
	require.ErrorIs(t, err, ErrGroupDoesNotFulfilRequirement)
	require.Equal(t, EnsureResultError, result)
	require.Zero(t, runner.mutationCnt)
}

func TestDarwinEnsureGroupRollsBackIncompleteCreation(t *testing.T) {
	fake := newFakeDarwinRunner()
	repository := newFakeNativeDarwinRepository(fake)
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			return path == darwinDSCLPath && len(args) >= 4 && args[1] == "-create" && args[3] == "PrimaryGroupID"
		},
	}

	_, result, err := repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "incomplete"}, nil)
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.NotContains(t, fake.groups, "incomplete")
}

func TestDarwinEnsureGroupRollsBackExistingUpdate(t *testing.T) {
	fake := newFakeDarwinRunner()
	fake.groups["developers"] = &fakeDarwinGroup{name: "developers", gid: 1001, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(fake)
	reads := 0
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			if path == darwinDSCLPath && len(args) >= 4 && args[0] == "-url" && args[2] == "-read" && args[3] == "/Groups/developers" {
				reads++
				return reads == 2
			}
			return false
		},
	}
	newGID := GroupId(1002)

	_, result, err := repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "developers", Gid: &newGID}, nil)
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.Equal(t, GroupId(1001), fake.groups["developers"].gid)
}

func TestDarwinEnsureGroupRejectsGIDChangeWhileUsedAsPrimary(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20}
	repository := newFakeNativeDarwinRepository(runner)
	newGID := GroupId(21)

	_, result, err := repository.EnsureGroup(t.Context(), &GroupRequirement{Name: "staff", Gid: &newGID}, nil)
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "primary group")
	require.Equal(t, GroupId(20), runner.groups["staff"].gid)
}

func TestDarwinEnsureUserCreateUpdateAndVerify(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.groups["primary"] = &fakeDarwinGroup{name: "primary", gid: 100, members: map[string]bool{}}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 200, members: map[string]bool{}}
	runner.groups["legacy"] = &fakeDarwinGroup{name: "legacy", gid: 300, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)
	home := false
	uid := Id(501)
	requirement := &Requirement{
		Name: "alice", DisplayName: "Alice Example", Uid: &uid,
		Group: GroupRequirement{Name: "primary"}, Groups: GroupRequirements{{Name: "staff"}},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}

	actual, result, err := repository.Ensure(t.Context(), requirement, &EnsureOpts{HomeDir: &home})
	require.NoError(t, err)
	require.Equal(t, EnsureResultCreated, result)
	require.Equal(t, &User{
		Name: "alice", DisplayName: "Alice Example", Uid: 501,
		Group: Group{Name: "primary", Gid: 100}, Groups: Groups{{Name: "staff", Gid: 200}},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}, actual)

	runner.groups["legacy"].members["alice"] = true
	newUID := Id(502)
	requirement.Uid = &newUID
	requirement.DisplayName = "Alice Updated"
	requirement.Groups = GroupRequirements{{Name: "legacy"}}
	actual, result, err = repository.Ensure(t.Context(), requirement, &EnsureOpts{HomeDir: &home})
	require.NoError(t, err)
	require.Equal(t, EnsureResultModified, result)
	require.Equal(t, newUID, actual.Uid)
	require.Equal(t, "Alice Updated", actual.DisplayName)
	require.Equal(t, Groups{{Name: "legacy", Gid: 300}}, actual.Groups)
	require.False(t, runner.groups["staff"].members["alice"])
}

func TestDarwinEnsureUserReadsAndRemovesUUIDMemberships(t *testing.T) {
	fake := newFakeDarwinRunner()
	fake.users["alice"] = &fakeDarwinUser{
		name: "alice", displayName: "Alice", uid: 501, gid: 100, shell: "/bin/zsh",
		home: "/Users/alice", generatedUID: "UUID-ALICE",
	}
	fake.groups["primary"] = &fakeDarwinGroup{name: "primary", gid: 100, members: map[string]bool{}}
	fake.groups["staff"] = &fakeDarwinGroup{
		name: "staff", gid: 200, members: map[string]bool{}, memberUIDs: map[string]bool{"UUID-ALICE": true},
	}
	fake.groups["legacy"] = &fakeDarwinGroup{name: "legacy", gid: 300, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(fake)
	home := false
	uid := Id(501)
	requirement := &Requirement{
		Name: "alice", DisplayName: "Alice", Uid: &uid,
		Group: GroupRequirement{Name: "primary"}, Groups: GroupRequirements{{Name: "staff"}},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}

	actual, result, err := repository.Ensure(t.Context(), requirement, &EnsureOpts{HomeDir: &home})
	require.NoError(t, err)
	require.Equal(t, EnsureResultUnchanged, result)
	require.Equal(t, Groups{{Name: "staff", Gid: 200}}, actual.Groups)

	requirement.Groups = GroupRequirements{{Name: "legacy"}}
	actual, result, err = repository.Ensure(t.Context(), requirement, &EnsureOpts{HomeDir: &home})
	require.NoError(t, err)
	require.Equal(t, EnsureResultModified, result)
	require.Equal(t, Groups{{Name: "legacy", Gid: 300}}, actual.Groups)
	require.False(t, fake.groups["staff"].memberUIDs["UUID-ALICE"])
}

func TestDarwinEnsureUserRollsBackExistingAttributesAndMemberships(t *testing.T) {
	fake := newFakeDarwinRunner()
	fake.users["alice"] = &fakeDarwinUser{
		name: "alice", displayName: "Alice", uid: 501, gid: 100, shell: "/bin/zsh",
		home: "/Users/alice", generatedUID: "UUID-ALICE",
	}
	fake.groups["primary"] = &fakeDarwinGroup{name: "primary", gid: 100, members: map[string]bool{}}
	fake.groups["staff"] = &fakeDarwinGroup{
		name: "staff", gid: 200, members: map[string]bool{"alice": true}, memberUIDs: map[string]bool{"UUID-ALICE": true},
	}
	fake.groups["legacy"] = &fakeDarwinGroup{name: "legacy", gid: 300, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(fake)
	reads := 0
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			if path == darwinDSCLPath && len(args) >= 4 && args[0] == "-url" && args[2] == "-read" && args[3] == "/Users/alice" {
				reads++
				if reads == 2 {
					fake.groups["staff"].members["bob"] = true
					return true
				}
			}
			return false
		},
	}
	home := false
	uid := Id(502)

	_, result, err := repository.Ensure(t.Context(), &Requirement{
		Name: "alice", DisplayName: "Changed", Uid: &uid,
		Group: GroupRequirement{Name: "primary"}, Groups: GroupRequirements{{Name: "legacy"}},
		Shell: "/bin/bash", HomeDir: "/Users/alice",
	}, &EnsureOpts{HomeDir: &home})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.Equal(t, Id(501), fake.users["alice"].uid)
	require.Equal(t, "Alice", fake.users["alice"].displayName)
	require.Equal(t, "/bin/zsh", fake.users["alice"].shell)
	require.True(t, fake.groups["staff"].members["alice"])
	require.True(t, fake.groups["staff"].members["bob"])
	require.True(t, fake.groups["staff"].memberUIDs["UUID-ALICE"])
	require.False(t, fake.groups["legacy"].members["alice"])
	require.False(t, fake.groups["legacy"].memberUIDs["UUID-ALICE"])
}

func TestDarwinEnsureUserRollsBackMembershipWhenVerificationReadFails(t *testing.T) {
	fake := newFakeDarwinRunner()
	fake.users["alice"] = &fakeDarwinUser{
		name: "alice", displayName: "Alice", uid: 501, gid: 100, shell: "/bin/zsh",
		home: "/Users/alice", generatedUID: "UUID-ALICE",
	}
	fake.groups["primary"] = &fakeDarwinGroup{name: "primary", gid: 100, members: map[string]bool{}}
	fake.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 200, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(fake)
	staffReads := 0
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			if path == darwinDSCLPath && len(args) >= 4 && args[0] == "-url" && args[2] == "-read" && args[3] == "/Groups/staff" {
				staffReads++
				return staffReads == 2
			}
			return false
		},
	}
	home := false
	uid := Id(501)

	_, result, err := repository.Ensure(t.Context(), &Requirement{
		Name: "alice", DisplayName: "Alice", Uid: &uid,
		Group: GroupRequirement{Name: "primary"}, Groups: GroupRequirements{{Name: "staff"}},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}, &EnsureOpts{HomeDir: &home})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.False(t, fake.groups["staff"].members["alice"])
	require.False(t, fake.groups["staff"].memberUIDs["UUID-ALICE"])
}

func TestDarwinEnsureUserRollsBackCreatedAccountAndGroups(t *testing.T) {
	fake := newFakeDarwinRunner()
	repository := newFakeNativeDarwinRepository(fake)
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			return path == darwinDSCLPath && len(args) == 3 && args[1] == "-create" && args[2] == "/Users/alice"
		},
	}
	home := false

	_, result, err := repository.Ensure(t.Context(), &Requirement{
		Name: "alice", Group: GroupRequirement{Name: "new-primary"}, Groups: GroupRequirements{{Name: "new-extra"}},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}, &EnsureOpts{HomeDir: &home})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.NotContains(t, fake.users, "alice")
	require.NotContains(t, fake.groups, "new-primary")
	require.NotContains(t, fake.groups, "new-extra")
}

func TestDarwinEnsureUserRollsBackIncompleteAccountRecord(t *testing.T) {
	fake := newFakeDarwinRunner()
	fake.groups["primary"] = &fakeDarwinGroup{name: "primary", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(fake)
	repository.commandRunner = &failingDarwinRunner{
		delegate: fake,
		fail: func(path string, args []string) bool {
			return path == darwinDSCLPath && len(args) == 5 && args[1] == "-create" && args[3] == "UserShell"
		},
	}
	home := false

	_, result, err := repository.Ensure(t.Context(), &Requirement{
		Name: "alice", Group: GroupRequirement{Name: "primary"}, Groups: GroupRequirements{},
		Shell: "/bin/zsh", HomeDir: "/Users/alice",
	}, &EnsureOpts{HomeDir: &home})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "injected Darwin command failure")
	require.NotContains(t, fake.users, "alice")
}

func TestDarwinEnsureRejectsUIDOnlyUpdateAndNonLocalCollision(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice", shell: "/bin/zsh"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)
	uid := Id(501)
	before := runner.mutationCnt

	_, result, err := repository.Ensure(t.Context(), &Requirement{Uid: &uid}, &EnsureOpts{HomeDir: common.P(false)})
	require.ErrorContains(t, err, "UID-only update")
	require.Equal(t, EnsureResultError, result)
	require.Equal(t, before, runner.mutationCnt)

	empty := newFakeDarwinRunner()
	repository = newFakeNativeDarwinRepository(empty)
	repository.lookupUserByName = func(string) (*osuser.User, error) {
		return &osuser.User{Username: "network-alice", Uid: "9001"}, nil
	}
	_, result, err = repository.Ensure(t.Context(), &Requirement{Name: "alice"}, &EnsureOpts{HomeDir: common.P(false)})
	require.ErrorContains(t, err, "non-local Darwin user")
	require.Equal(t, EnsureResultError, result)
	require.Zero(t, empty.mutationCnt)
}

func TestDarwinEnsureRejectsAmbiguousSearchPathBinding(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice", shell: "/bin/zsh"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)
	repository.lookupUserById = func(string) (*osuser.User, error) {
		return &osuser.User{Username: "network-alice", Uid: "501"}, nil
	}
	before := runner.mutationCnt

	_, result, err := repository.Ensure(t.Context(), &Requirement{Name: "alice"}, &EnsureOpts{HomeDir: common.P(false)})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "not uniquely bound")
	require.Equal(t, before, runner.mutationCnt)
}

func TestDarwinEnsureRejectsDuplicateGeneratedUID(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice", shell: "/bin/zsh", generatedUID: "00000000-0000-0000-0000-000000000001"}
	runner.users["bob"] = &fakeDarwinUser{name: "bob", uid: 502, gid: 20, home: "/Users/bob", shell: "/bin/zsh", generatedUID: "00000000-0000-0000-0000-000000000001"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)
	before := runner.mutationCnt

	_, result, err := repository.Ensure(t.Context(), &Requirement{Name: "alice"}, &EnsureOpts{HomeDir: common.P(false)})
	require.Equal(t, EnsureResultError, result)
	require.ErrorContains(t, err, "generated UID")
	require.Equal(t, before, runner.mutationCnt)
}

func TestDarwinDeleteRequiresLocalIdentityBinding(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)
	opts := &DeleteOpts{HomeDir: common.P(false), KillProcesses: common.P(false)}

	err := repository.DeleteByIdentity(t.Context(), 501, "mallory", "/Users/alice", opts)
	require.ErrorContains(t, err, "changed name")
	require.Contains(t, runner.users, "alice")

	err = repository.DeleteByIdentity(t.Context(), 501, "alice", "/Users/wrong", &DeleteOpts{HomeDir: common.P(true), KillProcesses: common.P(false)})
	require.ErrorContains(t, err, "changed home directory")
	require.Contains(t, runner.users, "alice")
	err = repository.DeleteByIdentity(t.Context(), 501, "alice", "", &DeleteOpts{HomeDir: common.P(true), KillProcesses: common.P(false)})
	require.ErrorContains(t, err, "changed home directory")
	require.Contains(t, runner.users, "alice")

	require.NoError(t, repository.DeleteByIdentity(t.Context(), 501, "alice", "/Users/alice", opts))
	require.NotContains(t, runner.users, "alice")
	require.ErrorIs(t, repository.DeleteById(t.Context(), 501, opts), ErrNoSuchUser)
}

func TestDarwinDeleteRemovesUUIDMemberships(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice", generatedUID: "UUID-ALICE"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	runner.groups["developers"] = &fakeDarwinGroup{
		name: "developers", gid: 21, members: map[string]bool{}, memberUIDs: map[string]bool{"UUID-ALICE": true},
	}
	repository := newFakeNativeDarwinRepository(runner)
	opts := &DeleteOpts{HomeDir: common.P(false), KillProcesses: common.P(false)}

	require.NoError(t, repository.DeleteByIdentity(t.Context(), 501, "alice", "/Users/alice", opts))
	require.NotContains(t, runner.users, "alice")
	require.False(t, runner.groups["developers"].memberUIDs["UUID-ALICE"])
}

func TestDarwinAbsentIdentityHomeCleanupRejectsReusedIdentity(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["replacement"] = &fakeDarwinUser{name: "replacement", uid: 501, gid: 20, home: "/Users/replacement"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)

	err := repository.DeleteHomeByAbsentIdentity(t.Context(), 501, "alice", "/Users/alice")
	require.ErrorContains(t, err, "UID 501 is no longer absent")
}

func TestDarwinDeleteRejectsUnsafeAndSharedHomesBeforeMutation(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/"}
	repository := newFakeNativeDarwinRepository(runner)
	opts := &DeleteOpts{HomeDir: common.P(true), KillProcesses: common.P(false)}
	before := runner.mutationCnt
	require.ErrorContains(t, repository.DeleteByIdentity(t.Context(), 501, "alice", "/", opts), "unsafe home")
	require.Equal(t, before, runner.mutationCnt)

	runner.users["alice"].home = "/Users/shared"
	runner.users["bob"] = &fakeDarwinUser{name: "bob", uid: 502, gid: 20, home: "/Users/shared"}
	require.ErrorContains(t, repository.DeleteByIdentity(t.Context(), 501, "alice", "/Users/shared", opts), "shared home")
	require.Equal(t, before, runner.mutationCnt)
}

func TestDarwinProcessCleanupRequiresIdentityOrConfirmedAbsence(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice"}
	repository := newFakeNativeDarwinRepository(runner)
	repository.processes = func(context.Context) ([]*process.Process, error) { return nil, nil }

	require.ErrorContains(t, repository.KillProcessesByIdentity(t.Context(), 501, "mallory"), "changed name")
	require.NoError(t, repository.KillProcessesByIdentity(t.Context(), 501, "alice"))
	require.NoError(t, repository.KillProcessesByAbsentIdentity(t.Context(), 999, "absent"))

	repository.lookupUserById = func(string) (*osuser.User, error) {
		return &osuser.User{Username: "reused", Uid: "999"}, nil
	}
	require.ErrorContains(t, repository.KillProcessesByAbsentIdentity(t.Context(), 999, "absent"), "no longer absent")
}

func TestDarwinDeleteGroupRejectsPrimaryGroupAndVerifiesDeletion(t *testing.T) {
	runner := newFakeDarwinRunner()
	runner.users["alice"] = &fakeDarwinUser{name: "alice", uid: 501, gid: 20, home: "/Users/alice"}
	runner.groups["staff"] = &fakeDarwinGroup{name: "staff", gid: 20, members: map[string]bool{}}
	runner.groups["unused"] = &fakeDarwinGroup{name: "unused", gid: 21, members: map[string]bool{}}
	repository := newFakeNativeDarwinRepository(runner)

	require.ErrorContains(t, repository.DeleteGroupByName(t.Context(), "staff", nil), "still used")
	require.NoError(t, repository.DeleteGroupById(t.Context(), 21, nil))
	require.NotContains(t, runner.groups, "unused")
}

type blockingDarwinRunner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (this *blockingDarwinRunner) Run(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	this.once.Do(func() { close(this.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-this.release:
		return fakeDarwinMissing()
	}
}

func TestDarwinMutationsAreSerializedAndCancellationAware(t *testing.T) {
	runner := &blockingDarwinRunner{started: make(chan struct{}), release: make(chan struct{})}
	repository := newFakeNativeDarwinRepository(runner)
	firstDone := make(chan error, 1)
	go func() {
		_, _, err := repository.EnsureGroup(context.Background(), &GroupRequirement{Name: "first"}, nil)
		firstDone <- err
	}()
	<-runner.started

	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	_, result, err := repository.EnsureGroup(ctx, &GroupRequirement{Name: "second"}, nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, EnsureResultError, result)

	close(runner.release)
	require.Error(t, <-firstDone)
}
