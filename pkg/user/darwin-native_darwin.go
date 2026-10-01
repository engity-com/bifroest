//go:build darwin

package user

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/process"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

const (
	darwinDSCLPath        = "/usr/bin/dscl"
	darwinDSCacheUtilPath = "/usr/bin/dscacheutil"
	darwinDSEditGroupPath = "/usr/sbin/dseditgroup"
	darwinLocalNode       = "/Local/Default"
	maxDarwinAllocatedID  = 1<<31 - 1
)

var darwinMutationMutex sync.Mutex

type darwinCommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type darwinExecCommandRunner struct{}

func (darwinExecCommandRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, path, args...).CombinedOutput()
}

type darwinProcessLister func(context.Context) ([]*process.Process, error)

type darwinUserRecord struct {
	name         string
	displayName  string
	uid          Id
	gid          GroupId
	shell        string
	homeDir      string
	generatedUID string
}

type darwinGroupRecord struct {
	name         string
	gid          GroupId
	members      []string
	memberUIDs   []string
	generatedUID string
}

type darwinMutation struct {
	rollbacks        []darwinRollback
	commits          []func(context.Context) error
	groupMemberships map[string]*darwinGroupMembershipRollback
}

type darwinRollback struct {
	action  func(context.Context) error
	timeout time.Duration
}

type darwinGroupMembershipRollback struct {
	group            string
	members          map[string]bool
	memberUID        string
	memberUIDPresent bool
}

func (this *darwinMutation) onRollback(action func(context.Context) error) {
	this.rollbacks = append(this.rollbacks, darwinRollback{action: action, timeout: 5 * time.Second})
}

func (this *darwinMutation) onFilesystemRollback(action func(context.Context) error) {
	this.rollbacks = append(this.rollbacks, darwinRollback{action: action})
}

func (this *darwinMutation) onCommit(action func(context.Context) error) {
	this.commits = append(this.commits, action)
}

func (this *darwinMutation) rollback(ctx context.Context) error {
	var result error
	for i := len(this.rollbacks) - 1; i >= 0; i-- {
		rollbackCtx := context.WithoutCancel(ctx)
		cancel := func() {}
		if this.rollbacks[i].timeout > 0 {
			rollbackCtx, cancel = context.WithTimeout(rollbackCtx, this.rollbacks[i].timeout)
		}
		result = stderrors.Join(result, this.rollbacks[i].action(rollbackCtx))
		cancel()
	}
	return result
}

func (this *darwinMutation) commit(ctx context.Context) error {
	for _, action := range this.commits {
		if err := action(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (this *DarwinRepository) runner() darwinCommandRunner {
	if this.commandRunner != nil {
		return this.commandRunner
	}
	return darwinExecCommandRunner{}
}

func (this *DarwinRepository) lockMutation(ctx context.Context) error {
	for !darwinMutationMutex.TryLock() {
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		darwinMutationMutex.Unlock()
		return err
	}
	return nil
}

func (this *DarwinRepository) runNative(ctx context.Context, path string, args ...string) ([]byte, error) {
	if path != darwinDSCLPath && path != darwinDSCacheUtilPath && path != darwinDSEditGroupPath {
		return nil, fmt.Errorf("refusing to execute unsupported Darwin account tool %q", path)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := this.runner().Run(ctx, path, args...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out, ctxErr
		}
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return out, err
		}
		return out, fmt.Errorf("%w: %s", err, detail)
	}
	return out, nil
}

func validateDarwinRecordName(name, kind string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00\r\n") {
		return fmt.Errorf("invalid Darwin %s record name %q", kind, name)
	}
	return nil
}

func darwinRecordPath(kind, name string) (string, error) {
	if err := validateDarwinRecordName(name, strings.ToLower(kind)); err != nil {
		return "", err
	}
	return "/" + kind + "/" + name, nil
}

func isMissingDarwinRecord(out []byte, err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(string(out) + " " + err.Error())
	return strings.Contains(message, "edsrecordnotfound") ||
		strings.Contains(message, "ds error: -14136") ||
		strings.Contains(message, "record was not found") ||
		strings.Contains(message, "no such key")
}

func decodeDarwinValue(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func parseDarwinAttributes(raw []byte) map[string][]string {
	result := make(map[string][]string)
	var current string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line == "-" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && current != "" {
			for _, value := range strings.Fields(line) {
				result[current] = append(result[current], decodeDarwinValue(value))
			}
			continue
		}
		key, values, found := strings.Cut(line, ":")
		if !found {
			current = ""
			continue
		}
		current = strings.TrimSpace(key)
		for _, value := range strings.Fields(values) {
			result[current] = append(result[current], decodeDarwinValue(value))
		}
	}
	return result
}

func parseDarwinReadAll(raw []byte) []map[string][]string {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	var parts []string
	var current strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "-" {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
	}
	parts = append(parts, current.String())
	result := make([]map[string][]string, 0, len(parts))
	for _, part := range parts {
		attrs := parseDarwinAttributes([]byte(part))
		if len(attrs) > 0 {
			result = append(result, attrs)
		}
	}
	return result
}

func firstDarwinAttribute(attrs map[string][]string, name string) string {
	values := attrs[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func darwinUserRecordFromAttributes(attrs map[string][]string) (*darwinUserRecord, error) {
	name := firstDarwinAttribute(attrs, "RecordName")
	uid, err := parseDarwinId(firstDarwinAttribute(attrs, "UniqueID"), "user")
	if err != nil {
		return nil, err
	}
	gid, err := parseDarwinId(firstDarwinAttribute(attrs, "PrimaryGroupID"), "primary group")
	if err != nil {
		return nil, err
	}
	return &darwinUserRecord{
		name:         name,
		displayName:  firstDarwinAttribute(attrs, "RealName"),
		uid:          Id(uid),
		gid:          GroupId(gid),
		shell:        firstDarwinAttribute(attrs, "UserShell"),
		homeDir:      firstDarwinAttribute(attrs, "NFSHomeDirectory"),
		generatedUID: firstDarwinAttribute(attrs, "GeneratedUID"),
	}, nil
}

func darwinGroupRecordFromAttributes(attrs map[string][]string) (*darwinGroupRecord, error) {
	name := firstDarwinAttribute(attrs, "RecordName")
	gid, err := parseDarwinId(firstDarwinAttribute(attrs, "PrimaryGroupID"), "group")
	if err != nil {
		return nil, err
	}
	return &darwinGroupRecord{
		name: name, gid: GroupId(gid), members: attrs["GroupMembership"], memberUIDs: attrs["GroupMembers"],
		generatedUID: firstDarwinAttribute(attrs, "GeneratedUID"),
	}, nil
}

func (this *DarwinRepository) readLocalRecord(ctx context.Context, kind, name string) (map[string][]string, error) {
	path, err := darwinRecordPath(kind, name)
	if err != nil {
		return nil, err
	}
	args := []string{"-url", darwinLocalNode, "-read", path}
	switch kind {
	case "Users":
		args = append(args, "RecordName", "UniqueID", "PrimaryGroupID", "RealName", "UserShell", "NFSHomeDirectory", "GeneratedUID")
	case "Groups":
		args = append(args, "RecordName", "PrimaryGroupID", "GroupMembership", "GroupMembers", "GeneratedUID")
	}
	out, err := this.runNative(ctx, darwinDSCLPath, args...)
	if err != nil {
		if isMissingDarwinRecord(out, err) {
			return nil, nil
		}
		return nil, berrors.Newf(berrors.System, "cannot read local Darwin %s %q: %w", strings.ToLower(kind), name, err)
	}
	return parseDarwinAttributes(out), nil
}

func (this *DarwinRepository) readAllLocalRecords(ctx context.Context, kind string, attributes ...string) ([]map[string][]string, error) {
	args := []string{"-url", darwinLocalNode, "-readall", "/" + kind}
	args = append(args, attributes...)
	out, err := this.runNative(ctx, darwinDSCLPath, args...)
	if err != nil {
		return nil, berrors.Newf(berrors.System, "cannot list local Darwin %s: %w", strings.ToLower(kind), err)
	}
	return parseDarwinReadAll(out), nil
}

func (this *DarwinRepository) localUserByName(ctx context.Context, name string) (*darwinUserRecord, error) {
	attrs, err := this.readLocalRecord(ctx, "Users", name)
	if err != nil || attrs == nil {
		return nil, err
	}
	result, err := darwinUserRecordFromAttributes(attrs)
	if err != nil {
		return nil, err
	}
	if result.name != name {
		return nil, fmt.Errorf("local Darwin user record %q resolved to unexpected name %q", name, result.name)
	}
	return result, nil
}

func (this *DarwinRepository) allLocalUsers(ctx context.Context) ([]*darwinUserRecord, error) {
	records, err := this.readAllLocalRecords(ctx, "Users", "RecordName", "UniqueID", "PrimaryGroupID", "RealName", "UserShell", "NFSHomeDirectory", "GeneratedUID")
	if err != nil {
		return nil, err
	}
	result := make([]*darwinUserRecord, 0, len(records))
	for _, attrs := range records {
		record, err := darwinUserRecordFromAttributes(attrs)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func (this *DarwinRepository) localUserByID(ctx context.Context, id Id) (*darwinUserRecord, error) {
	users, err := this.allLocalUsers(ctx)
	if err != nil {
		return nil, err
	}
	var result *darwinUserRecord
	for _, candidate := range users {
		if candidate.uid == id {
			if result != nil {
				return nil, fmt.Errorf("darwin UID %d is assigned to multiple local users", id)
			}
			result = candidate
		}
	}
	return result, nil
}

func (this *DarwinRepository) localGroupByName(ctx context.Context, name string) (*darwinGroupRecord, error) {
	attrs, err := this.readLocalRecord(ctx, "Groups", name)
	if err != nil || attrs == nil {
		return nil, err
	}
	result, err := darwinGroupRecordFromAttributes(attrs)
	if err != nil {
		return nil, err
	}
	if result.name != name {
		return nil, fmt.Errorf("local Darwin group record %q resolved to unexpected name %q", name, result.name)
	}
	return result, nil
}

func (this *DarwinRepository) allLocalGroups(ctx context.Context) ([]*darwinGroupRecord, error) {
	records, err := this.readAllLocalRecords(ctx, "Groups", "RecordName", "PrimaryGroupID", "GroupMembership", "GroupMembers", "GeneratedUID")
	if err != nil {
		return nil, err
	}
	result := make([]*darwinGroupRecord, 0, len(records))
	for _, attrs := range records {
		record, err := darwinGroupRecordFromAttributes(attrs)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

func (this *DarwinRepository) localGroupByID(ctx context.Context, id GroupId) (*darwinGroupRecord, error) {
	groups, err := this.allLocalGroups(ctx)
	if err != nil {
		return nil, err
	}
	var result *darwinGroupRecord
	for _, candidate := range groups {
		if candidate.gid == id {
			if result != nil {
				return nil, fmt.Errorf("darwin GID %d is assigned to multiple local groups", id)
			}
			result = candidate
		}
	}
	return result, nil
}

func (this *DarwinRepository) localUserToUser(ctx context.Context, record *darwinUserRecord) (*User, error) {
	groups, err := this.allLocalGroups(ctx)
	if err != nil {
		return nil, err
	}
	var primary *Group
	supplementary := make(Groups, 0)
	for _, candidate := range groups {
		group := Group{Gid: candidate.gid, Name: candidate.name}
		if candidate.gid == record.gid {
			copy := group
			primary = &copy
		}
		if candidate.gid != record.gid && darwinGroupContainsUser(candidate, record) {
			supplementary = append(supplementary, group)
		}
	}
	if primary == nil {
		return nil, fmt.Errorf("cannot resolve local primary group %d of Darwin user %q", record.gid, record.name)
	}
	sort.Slice(supplementary, func(i, j int) bool {
		if supplementary[i].Gid == supplementary[j].Gid {
			return supplementary[i].Name < supplementary[j].Name
		}
		return supplementary[i].Gid < supplementary[j].Gid
	})
	return &User{
		Name:        record.name,
		DisplayName: record.displayName,
		Uid:         record.uid,
		Group:       *primary,
		Groups:      supplementary,
		Shell:       record.shell,
		HomeDir:     record.homeDir,
	}, nil
}

func containsDarwinString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsDarwinUUID(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func darwinGroupContainsUser(group *darwinGroupRecord, user *darwinUserRecord) bool {
	return containsDarwinString(group.members, user.name) ||
		(user.generatedUID != "" && containsDarwinUUID(group.memberUIDs, user.generatedUID))
}

func (this *DarwinRepository) lookupLocalUserRequirement(ctx context.Context, req *Requirement) (*darwinUserRecord, error) {
	if req.Name != "" {
		result, err := this.localUserByName(ctx, req.Name)
		if err != nil || result != nil {
			return result, err
		}
	}
	if req.Uid != nil {
		return this.localUserByID(ctx, *req.Uid)
	}
	return nil, nil
}

func (this *DarwinRepository) lookupLocalGroupRequirement(ctx context.Context, req *GroupRequirement) (*darwinGroupRecord, error) {
	if req.Name != "" {
		result, err := this.localGroupByName(ctx, req.Name)
		if err != nil || result != nil {
			return result, err
		}
	}
	if req.Gid != nil {
		return this.localGroupByID(ctx, *req.Gid)
	}
	return nil, nil
}

func (this *DarwinRepository) verifyDarwinUserBinding(ctx context.Context, record *darwinUserRecord) error {
	byName, err := this.userByName(record.name)
	if err != nil {
		return fmt.Errorf("cannot verify local Darwin user %q in the account search path: %w", record.name, err)
	}
	nameUID, err := parseDarwinId(byName.Uid, "user")
	if err != nil || byName.Username != record.name || Id(nameUID) != record.uid {
		return fmt.Errorf("local Darwin user %d(%s) is not uniquely bound in the account search path", record.uid, record.name)
	}
	byID, err := this.userById(record.uid.String())
	if err != nil {
		return fmt.Errorf("cannot verify local Darwin UID %d in the account search path: %w", record.uid, err)
	}
	idUID, err := parseDarwinId(byID.Uid, "user")
	if err != nil || byID.Username != record.name || Id(idUID) != record.uid {
		return fmt.Errorf("local Darwin user %d(%s) is not uniquely bound in the account search path", record.uid, record.name)
	}
	if record.generatedUID != "" {
		users, err := this.allLocalUsers(ctx)
		if err != nil {
			return err
		}
		for _, candidate := range users {
			if candidate.name != record.name && strings.EqualFold(candidate.generatedUID, record.generatedUID) {
				return fmt.Errorf("darwin generated UID %q is assigned to multiple local users", record.generatedUID)
			}
		}
		groups, err := this.allLocalGroups(ctx)
		if err != nil {
			return err
		}
		for _, candidate := range groups {
			if strings.EqualFold(candidate.generatedUID, record.generatedUID) {
				return fmt.Errorf("darwin generated UID %q is shared by local user %q and group %q", record.generatedUID, record.name, candidate.name)
			}
		}
	}
	return nil
}

func (this *DarwinRepository) verifyDarwinGroupBinding(record *darwinGroupRecord) error {
	byName, err := this.groupByName(record.name)
	if err != nil {
		return fmt.Errorf("cannot verify local Darwin group %q in the group search path: %w", record.name, err)
	}
	nameGID, err := parseDarwinId(byName.Gid, "group")
	if err != nil || byName.Name != record.name || GroupId(nameGID) != record.gid {
		return fmt.Errorf("local Darwin group %d(%s) is not uniquely bound in the group search path", record.gid, record.name)
	}
	byID, err := this.groupById(record.gid.String())
	if err != nil {
		return fmt.Errorf("cannot verify local Darwin GID %d in the group search path: %w", record.gid, err)
	}
	idGID, err := parseDarwinId(byID.Gid, "group")
	if err != nil || byID.Name != record.name || GroupId(idGID) != record.gid {
		return fmt.Errorf("local Darwin group %d(%s) is not uniquely bound in the group search path", record.gid, record.name)
	}
	return nil
}

func darwinRequirementDefaults(req *Requirement) Requirement {
	result := req.Clone()
	if result.Name == "" && result.Uid != nil {
		result.Name = "u" + result.Uid.String()
	}
	if result.HomeDir == "" && result.Name != "" {
		result.HomeDir = filepath.Join("/Users", result.Name)
	}
	if result.Group.IsZero() {
		result.Group = GroupRequirement{Name: result.Name}
	}
	if result.Groups.IsZero() {
		result.Groups = GroupRequirements{{Name: defaultGroupName}}
	}
	if result.Shell == "" {
		result.Shell = "/bin/sh"
	}
	return result
}

func darwinGroupRequirementMatches(req *GroupRequirement, group *Group) bool {
	return group != nil && (req.Name == "" || req.Name == group.Name) && (req.Gid == nil || *req.Gid == group.Gid)
}

func darwinGroupsMatch(reqs GroupRequirements, groups Groups) bool {
	if len(reqs) != len(groups) {
		return false
	}
	used := make([]bool, len(groups))
	for i := range reqs {
		matched := false
		for j := range groups {
			if !used[j] && darwinGroupRequirementMatches(&reqs[i], &groups[j]) {
				used[j] = true
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func darwinUserRequirementMatches(req *Requirement, actual *User) bool {
	return actual != nil &&
		(req.Name == "" || req.Name == actual.Name) &&
		(req.Uid == nil || *req.Uid == actual.Uid) &&
		req.DisplayName == actual.DisplayName &&
		darwinGroupRequirementMatches(&req.Group, &actual.Group) &&
		darwinGroupsMatch(req.Groups, actual.Groups) &&
		req.Shell == actual.Shell &&
		req.HomeDir == actual.HomeDir
}

func (this *DarwinRepository) Ensure(ctx context.Context, req *Requirement, opts *EnsureOpts) (_ *User, _ EnsureResult, rErr error) {
	if req == nil {
		panic("nil user requirement")
	}
	if err := this.lockMutation(ctx); err != nil {
		return nil, EnsureResultError, err
	}
	defer darwinMutationMutex.Unlock()
	transaction := &darwinMutation{}
	committed := false
	defer func() {
		if !committed {
			if err := transaction.rollback(ctx); err != nil {
				rErr = stderrors.Join(rErr, fmt.Errorf("cannot roll back incomplete Darwin account provisioning: %w", err))
			}
		}
	}()

	tReq := darwinRequirementDefaults(req)
	if err := validateDarwinRecordName(tReq.Name, "user"); err != nil {
		return nil, EnsureResultError, err
	}
	existing, err := this.lookupLocalUserRequirement(ctx, &tReq)
	if err != nil {
		return nil, EnsureResultError, err
	}
	var current *User
	if existing != nil {
		if err := this.verifyDarwinUserBinding(ctx, existing); err != nil {
			return nil, EnsureResultError, err
		}
		current, err = this.localUserToUser(ctx, existing)
		if err != nil {
			return nil, EnsureResultError, err
		}
		if darwinUserRequirementMatches(&tReq, current) {
			return current, EnsureResultUnchanged, nil
		}
		if req.Name == "" {
			return nil, EnsureResultError, fmt.Errorf("refusing UID-only update of local Darwin user %d", existing.uid)
		}
		if !opts.IsModifyAllowed() {
			return nil, EnsureResultError, ErrUserDoesNotFulfilRequirement
		}
	} else {
		if !opts.IsCreateAllowed() {
			return nil, EnsureResultError, ErrNoSuchUser
		}
		if err := this.rejectNonLocalUserCollision(&tReq); err != nil {
			return nil, EnsureResultError, err
		}
	}

	created := existing == nil
	oldName, oldHome := "", ""
	oldUID := Id(0)
	if existing != nil {
		oldName, oldHome, oldUID = existing.name, existing.homeDir, existing.uid
		if oldName != tReq.Name {
			if err := this.rejectNonLocalUserNameCollision(tReq.Name); err != nil {
				return nil, EnsureResultError, err
			}
		}
	}
	uid := Id(0)
	if tReq.Uid != nil {
		uid = *tReq.Uid
	} else if existing != nil {
		uid = existing.uid
	} else {
		uid, err = this.nextLocalUID(ctx)
		if err != nil {
			return nil, EnsureResultError, err
		}
	}
	if collision, err := this.localUserByID(ctx, uid); err != nil {
		return nil, EnsureResultError, err
	} else if collision != nil && (existing == nil || collision.name != existing.name) {
		return nil, EnsureResultError, fmt.Errorf("darwin UID %d is already assigned to local user %q", uid, collision.name)
	}
	if existing == nil || existing.uid != uid {
		if native, err := this.userById(uid.String()); err == nil {
			return nil, EnsureResultError, fmt.Errorf("darwin UID %d is already assigned to user %q", uid, native.Username)
		} else if !isUnknownDarwinUser(err) {
			return nil, EnsureResultError, fmt.Errorf("cannot verify Darwin UID %d is unused: %w", uid, err)
		}
	}

	primaryRecord, primary, _, err := this.ensureGroupLocked(ctx, &tReq.Group, opts, transaction)
	if err != nil {
		return nil, EnsureResultError, err
	}
	desiredGroups := make(Groups, 0, len(tReq.Groups))
	desiredGroupIDs := make(map[GroupId]struct{}, len(tReq.Groups))
	for i := range tReq.Groups {
		_, group, _, err := this.ensureGroupLocked(ctx, &tReq.Groups[i], opts, transaction)
		if err != nil {
			return nil, EnsureResultError, err
		}
		if group.Gid == primary.Gid {
			return nil, EnsureResultError, fmt.Errorf("primary group %q cannot also be a supplementary group", group.Name)
		}
		if _, exists := desiredGroupIDs[group.Gid]; exists {
			return nil, EnsureResultError, fmt.Errorf("supplementary group %q is required more than once", group.Name)
		}
		desiredGroupIDs[group.Gid] = struct{}{}
		desiredGroups = append(desiredGroups, *group)
	}

	path, _ := darwinRecordPath("Users", tReq.Name)
	generatedUID := ""
	if existing != nil {
		generatedUID = existing.generatedUID
	} else {
		generatedUID = strings.ToUpper(uuid.NewString())
	}
	if created {
		if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-create", path); err != nil {
			return nil, EnsureResultError, berrors.Newf(berrors.System, "cannot create local Darwin user %q: %w", tReq.Name, err)
		}
		transaction.onRollback(func(ctx context.Context) error {
			_, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-delete", path)
			return err
		})
		if err := this.setLocalAttribute(ctx, path, "GeneratedUID", generatedUID); err != nil {
			return nil, EnsureResultError, err
		}
	} else if oldName != tReq.Name {
		oldPath, _ := darwinRecordPath("Users", oldName)
		if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-change", oldPath, "RecordName", oldName, tReq.Name); err != nil {
			return nil, EnsureResultError, berrors.Newf(berrors.System, "cannot rename local Darwin user %q to %q: %w", oldName, tReq.Name, err)
		}
		transaction.onRollback(func(ctx context.Context) error {
			_, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-change", path, "RecordName", tReq.Name, oldName)
			return err
		})
	}

	attributes := [][2]string{
		{"UniqueID", uid.String()},
		{"PrimaryGroupID", primaryRecord.gid.String()},
		{"RealName", tReq.DisplayName},
		{"UserShell", tReq.Shell},
		{"NFSHomeDirectory", tReq.HomeDir},
	}
	previousAttributes := map[string]string{}
	if existing != nil {
		previousAttributes = map[string]string{
			"UniqueID":         existing.uid.String(),
			"PrimaryGroupID":   existing.gid.String(),
			"RealName":         existing.displayName,
			"UserShell":        existing.shell,
			"NFSHomeDirectory": existing.homeDir,
		}
	}
	for _, attribute := range attributes {
		if err := this.setLocalAttribute(ctx, path, attribute[0], attribute[1]); err != nil {
			return nil, EnsureResultError, err
		}
		if existing != nil && previousAttributes[attribute[0]] != attribute[1] {
			name, value := attribute[0], previousAttributes[attribute[0]]
			transaction.onRollback(func(ctx context.Context) error {
				return this.setLocalAttribute(ctx, path, name, value)
			})
		}
	}

	currentGroups, err := this.allLocalGroups(ctx)
	if err != nil {
		return nil, EnsureResultError, err
	}
	desiredNames := make(map[string]struct{}, len(desiredGroups))
	for _, group := range desiredGroups {
		desiredNames[group.Name] = struct{}{}
	}
	oldIdentity := &darwinUserRecord{name: oldName, generatedUID: generatedUID}
	if existing != nil {
		oldIdentity.generatedUID = existing.generatedUID
	}
	currentIdentity := &darwinUserRecord{name: tReq.Name, generatedUID: generatedUID}
	for _, group := range currentGroups {
		wasMember := darwinGroupContainsUser(group, oldIdentity) || darwinGroupContainsUser(group, currentIdentity)
		isMember := darwinGroupContainsUser(group, currentIdentity)
		_, shouldBeMember := desiredNames[group.name]
		needsRenameRefresh := shouldBeMember && oldName != tReq.Name && containsDarwinString(group.members, oldName)
		if shouldBeMember && (!isMember || needsRenameRefresh) {
			if err := this.mutateDarwinGroupMembership(group, []string{oldName, tReq.Name}, generatedUID, transaction, func() error {
				return this.editLocalGroupMember(ctx, group.name, tReq.Name, true)
			}); err != nil {
				return nil, EnsureResultError, err
			}
		}
		if wasMember && !shouldBeMember {
			if err := this.mutateDarwinGroupMembership(group, []string{oldName, tReq.Name}, generatedUID, transaction, func() error {
				return this.editLocalGroupMember(ctx, group.name, tReq.Name, false)
			}); err != nil {
				return nil, EnsureResultError, err
			}
		}
		if oldName != tReq.Name && containsDarwinString(group.members, oldName) {
			if err := this.mutateDarwinGroupMembership(group, []string{oldName, tReq.Name}, generatedUID, transaction, func() error {
				return this.deleteLocalAttributeValue(ctx, "Groups", group.name, "GroupMembership", oldName)
			}); err != nil {
				return nil, EnsureResultError, err
			}
		}
		if shouldBeMember || wasMember {
			updated, err := this.localGroupByName(ctx, group.name)
			if err != nil {
				return nil, EnsureResultError, err
			}
			if updated == nil || darwinGroupContainsUser(updated, currentIdentity) != shouldBeMember {
				return nil, EnsureResultError, fmt.Errorf("local Darwin group %q has unexpected membership for user %q after mutation", group.name, tReq.Name)
			}
		}
	}

	if opts.IsHomeDir() {
		if created {
			err = this.createDarwinHome(ctx, tReq.Name, uid, primary.Gid, tReq.Skel, tReq.HomeDir, opts.GetOnHomeDirExist(), transaction)
		} else if oldHome != tReq.HomeDir {
			err = this.moveDarwinHome(ctx, tReq.Name, oldUID, uid, primary.Gid, oldHome, tReq.HomeDir, opts.GetOnHomeDirExist(), transaction)
		} else if oldUID != uid || current.Group.Gid != primary.Gid {
			if err = this.ensureDarwinHomeNotShared(ctx, tReq.HomeDir, tReq.Name); err == nil {
				var ownership []darwinHomeOwnership
				ownership, err = snapshotDarwinHomeOwnership(tReq.HomeDir)
				if err == nil {
					transaction.onFilesystemRollback(func(ctx context.Context) error {
						return restoreDarwinHomeOwnership(ctx, tReq.HomeDir, ownership)
					})
					err = this.chownOwnedDarwinHome(ctx, tReq.HomeDir, oldUID, uid, primary.Gid)
				}
			}
		}
		if err != nil {
			return nil, EnsureResultError, err
		}
	}

	verifiedRecord, err := this.localUserByName(ctx, tReq.Name)
	if err != nil {
		return nil, EnsureResultError, err
	}
	if verifiedRecord == nil {
		return nil, EnsureResultError, fmt.Errorf("local Darwin user %q disappeared after mutation", tReq.Name)
	}
	if err := this.verifyDarwinUserBinding(ctx, verifiedRecord); err != nil {
		return nil, EnsureResultError, err
	}
	verified, err := this.localUserToUser(ctx, verifiedRecord)
	if err != nil {
		return nil, EnsureResultError, err
	}
	if !darwinUserRequirementMatches(&tReq, verified) {
		return nil, EnsureResultError, fmt.Errorf("local Darwin user %q does not satisfy its requirement after mutation", tReq.Name)
	}
	committed = true
	if err := transaction.commit(ctx); err != nil {
		return nil, EnsureResultError, fmt.Errorf("cannot commit Darwin account provisioning: %w", err)
	}
	if created {
		return verified, EnsureResultCreated, nil
	}
	return verified, EnsureResultModified, nil
}

func (this *DarwinRepository) setLocalAttribute(ctx context.Context, path, name, value string) error {
	var args []string
	if value == "" {
		args = []string{darwinLocalNode, "-delete", path, name}
	} else {
		args = []string{darwinLocalNode, "-create", path, name, value}
	}
	out, err := this.runNative(ctx, darwinDSCLPath, args...)
	if value == "" && isMissingDarwinRecord(out, err) {
		return nil
	}
	if err != nil {
		return berrors.Newf(berrors.System, "cannot set %s on local Darwin record %q: %w", name, path, err)
	}
	return nil
}

func (this *DarwinRepository) deleteLocalAttributeValue(ctx context.Context, kind, record, name, value string) error {
	path, err := darwinRecordPath(kind, record)
	if err != nil {
		return err
	}
	out, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-delete", path, name, value)
	if isMissingDarwinRecord(out, err) {
		return nil
	}
	return err
}

func (this *DarwinRepository) mergeLocalAttributeValue(ctx context.Context, kind, record, name, value string) error {
	path, err := darwinRecordPath(kind, record)
	if err != nil {
		return err
	}
	_, err = this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-merge", path, name, value)
	return err
}

func (this *DarwinRepository) purgeLocalGroupMembershipValues(ctx context.Context, group *darwinGroupRecord, user *darwinUserRecord) error {
	var result error
	if containsDarwinString(group.members, user.name) {
		result = stderrors.Join(result, this.deleteLocalAttributeValue(ctx, "Groups", group.name, "GroupMembership", user.name))
	}
	if user.generatedUID != "" && containsDarwinUUID(group.memberUIDs, user.generatedUID) {
		result = stderrors.Join(result, this.deleteLocalAttributeValue(ctx, "Groups", group.name, "GroupMembers", user.generatedUID))
	}
	return result
}

func (this *DarwinRepository) registerDarwinGroupMembershipRollback(group *darwinGroupRecord, names []string, memberUID string, transaction *darwinMutation) {
	if transaction.groupMemberships == nil {
		transaction.groupMemberships = map[string]*darwinGroupMembershipRollback{}
	}
	rollback := transaction.groupMemberships[group.name]
	if rollback == nil {
		rollback = &darwinGroupMembershipRollback{
			group: group.name, members: map[string]bool{}, memberUID: memberUID,
			memberUIDPresent: memberUID != "" && containsDarwinUUID(group.memberUIDs, memberUID),
		}
		transaction.groupMemberships[group.name] = rollback
		transaction.onRollback(func(ctx context.Context) error {
			var result error
			for member, present := range rollback.members {
				if present {
					result = stderrors.Join(result, this.mergeLocalAttributeValue(ctx, "Groups", rollback.group, "GroupMembership", member))
				} else {
					result = stderrors.Join(result, this.deleteLocalAttributeValue(ctx, "Groups", rollback.group, "GroupMembership", member))
				}
			}
			if rollback.memberUID != "" {
				if rollback.memberUIDPresent {
					result = stderrors.Join(result, this.mergeLocalAttributeValue(ctx, "Groups", rollback.group, "GroupMembers", rollback.memberUID))
				} else {
					result = stderrors.Join(result, this.deleteLocalAttributeValue(ctx, "Groups", rollback.group, "GroupMembers", rollback.memberUID))
				}
			}
			return result
		})
	}
	for _, name := range names {
		if name != "" {
			if _, registered := rollback.members[name]; !registered {
				rollback.members[name] = containsDarwinString(group.members, name)
			}
		}
	}
}

func (this *DarwinRepository) mutateDarwinGroupMembership(group *darwinGroupRecord, names []string, memberUID string, transaction *darwinMutation, action func() error) error {
	this.registerDarwinGroupMembershipRollback(group, names, memberUID, transaction)
	return action()
}

func (this *DarwinRepository) editLocalGroupMember(ctx context.Context, group, name string, add bool) error {
	operation := "-a"
	if !add {
		operation = "-d"
	}
	_, err := this.runNative(ctx, darwinDSEditGroupPath, "-o", "edit", "-n", darwinLocalNode, operation, name, "-t", "user", group)
	if err != nil {
		return berrors.Newf(berrors.System, "cannot update membership of local Darwin group %q: %w", group, err)
	}
	return nil
}

func (this *DarwinRepository) EnsureGroup(ctx context.Context, req *GroupRequirement, opts *EnsureOpts) (_ *Group, _ EnsureResult, rErr error) {
	if req == nil {
		panic("nil group requirement")
	}
	if err := this.lockMutation(ctx); err != nil {
		return nil, EnsureResultError, err
	}
	defer darwinMutationMutex.Unlock()
	transaction := &darwinMutation{}
	committed := false
	defer func() {
		if !committed {
			rErr = stderrors.Join(rErr, transaction.rollback(ctx))
		}
	}()
	_, group, result, err := this.ensureGroupLocked(ctx, req, opts, transaction)
	if err != nil {
		return nil, EnsureResultError, err
	}
	committed = true
	if err := transaction.commit(ctx); err != nil {
		return nil, EnsureResultError, err
	}
	return group, result, err
}

func (this *DarwinRepository) ensureGroupLocked(ctx context.Context, req *GroupRequirement, opts *EnsureOpts, transaction *darwinMutation) (_ *darwinGroupRecord, _ *Group, _ EnsureResult, rErr error) {
	tReq := req.OrDefaults()
	if err := validateDarwinRecordName(tReq.Name, "group"); err != nil {
		return nil, nil, EnsureResultError, err
	}
	existing, err := this.lookupLocalGroupRequirement(ctx, &tReq)
	if err != nil {
		return nil, nil, EnsureResultError, err
	}
	if existing != nil {
		if err := this.verifyDarwinGroupBinding(existing); err != nil {
			return nil, nil, EnsureResultError, err
		}
	}
	if existing != nil && (tReq.Gid == nil || *tReq.Gid == existing.gid) && tReq.Name == existing.name {
		group := &Group{Gid: existing.gid, Name: existing.name}
		return existing, group, EnsureResultUnchanged, nil
	}
	if existing == nil {
		if !opts.IsCreateAllowed() {
			return nil, nil, EnsureResultError, ErrNoSuchGroup
		}
		if err := this.rejectNonLocalGroupCollision(&tReq); err != nil {
			return nil, nil, EnsureResultError, err
		}
	} else if !opts.IsModifyAllowed() {
		return existing, nil, EnsureResultError, ErrGroupDoesNotFulfilRequirement
	}

	gid := GroupId(0)
	if tReq.Gid != nil {
		gid = *tReq.Gid
	} else if existing != nil {
		gid = existing.gid
	} else {
		gid, err = this.nextLocalGID(ctx)
		if err != nil {
			return nil, nil, EnsureResultError, err
		}
	}
	if collision, err := this.localGroupByID(ctx, gid); err != nil {
		return nil, nil, EnsureResultError, err
	} else if collision != nil && (existing == nil || collision.name != existing.name) {
		return nil, nil, EnsureResultError, fmt.Errorf("darwin GID %d is already assigned to local group %q", gid, collision.name)
	}
	if existing == nil || existing.gid != gid {
		if native, err := this.groupById(gid.String()); err == nil {
			return nil, nil, EnsureResultError, fmt.Errorf("darwin GID %d is already assigned to group %q", gid, native.Name)
		} else if !isUnknownDarwinGroup(err) {
			return nil, nil, EnsureResultError, fmt.Errorf("cannot verify Darwin GID %d is unused: %w", gid, err)
		}
	}
	if existing != nil && existing.gid != gid {
		users, err := this.allLocalUsers(ctx)
		if err != nil {
			return nil, nil, EnsureResultError, err
		}
		for _, candidate := range users {
			if candidate.gid == existing.gid {
				return nil, nil, EnsureResultError, fmt.Errorf("cannot change GID of Darwin group %q while it is a primary group of user %d(%s)", existing.name, candidate.uid, candidate.name)
			}
		}
	}

	created := existing == nil
	path, _ := darwinRecordPath("Groups", tReq.Name)
	if created {
		if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-create", path); err != nil {
			return nil, nil, EnsureResultError, berrors.Newf(berrors.System, "cannot create local Darwin group %q: %w", tReq.Name, err)
		}
		transaction.onRollback(func(ctx context.Context) error {
			_, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-delete", path)
			return err
		})
		if err := this.setLocalAttribute(ctx, path, "GeneratedUID", strings.ToUpper(uuid.NewString())); err != nil {
			return nil, nil, EnsureResultError, err
		}
	} else if existing.name != tReq.Name {
		if err := this.rejectNonLocalGroupNameCollision(tReq.Name); err != nil {
			return nil, nil, EnsureResultError, err
		}
		oldPath, _ := darwinRecordPath("Groups", existing.name)
		if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-change", oldPath, "RecordName", existing.name, tReq.Name); err != nil {
			return nil, nil, EnsureResultError, berrors.Newf(berrors.System, "cannot rename local Darwin group %q to %q: %w", existing.name, tReq.Name, err)
		}
		oldName := existing.name
		transaction.onRollback(func(ctx context.Context) error {
			_, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-change", path, "RecordName", tReq.Name, oldName)
			return err
		})
	}
	if err := this.setLocalAttribute(ctx, path, "PrimaryGroupID", gid.String()); err != nil {
		return nil, nil, EnsureResultError, err
	}
	if existing != nil && existing.gid != gid {
		oldGID := existing.gid
		transaction.onRollback(func(ctx context.Context) error {
			return this.setLocalAttribute(ctx, path, "PrimaryGroupID", oldGID.String())
		})
	}
	verified, err := this.localGroupByName(ctx, tReq.Name)
	if err != nil {
		return nil, nil, EnsureResultError, err
	}
	if verified == nil || verified.gid != gid {
		return nil, nil, EnsureResultError, fmt.Errorf("local Darwin group %q does not satisfy its requirement after mutation", tReq.Name)
	}
	if err := this.verifyDarwinGroupBinding(verified); err != nil {
		return nil, nil, EnsureResultError, err
	}
	group := &Group{Gid: verified.gid, Name: verified.name}
	if created {
		return verified, group, EnsureResultCreated, nil
	}
	return verified, group, EnsureResultModified, nil
}

func (this *DarwinRepository) nextLocalUID(ctx context.Context) (Id, error) {
	users, err := this.allLocalUsers(ctx)
	if err != nil {
		return 0, err
	}
	used := make(map[Id]struct{}, len(users))
	var candidate Id = 1000
	for _, user := range users {
		used[user.uid] = struct{}{}
		if user.uid >= candidate && user.uid < maxDarwinAllocatedID && user.uid != 65534 {
			candidate = user.uid + 1
		}
	}
	for {
		if candidate == 65534 {
			candidate++
		}
		if _, exists := used[candidate]; !exists {
			if _, err := this.userById(candidate.String()); isUnknownDarwinUser(err) {
				return candidate, nil
			} else if err != nil {
				return 0, fmt.Errorf("cannot verify Darwin UID %d is unused: %w", candidate, err)
			}
		}
		if candidate >= maxDarwinAllocatedID {
			return 0, fmt.Errorf("no unused Darwin UID available")
		}
		candidate++
	}
}

func (this *DarwinRepository) nextLocalGID(ctx context.Context) (GroupId, error) {
	groups, err := this.allLocalGroups(ctx)
	if err != nil {
		return 0, err
	}
	used := make(map[GroupId]struct{}, len(groups))
	var candidate GroupId = 1000
	for _, group := range groups {
		used[group.gid] = struct{}{}
		if group.gid >= candidate && group.gid < maxDarwinAllocatedID && group.gid != 65534 {
			candidate = group.gid + 1
		}
	}
	for {
		if candidate == 65534 {
			candidate++
		}
		if _, exists := used[candidate]; !exists {
			if _, err := this.groupById(candidate.String()); isUnknownDarwinGroup(err) {
				return candidate, nil
			} else if err != nil {
				return 0, fmt.Errorf("cannot verify Darwin GID %d is unused: %w", candidate, err)
			}
		}
		if candidate >= maxDarwinAllocatedID {
			return 0, fmt.Errorf("no unused Darwin GID available")
		}
		candidate++
	}
}

func (this *DarwinRepository) rejectNonLocalUserCollision(req *Requirement) error {
	if req.Name != "" {
		if native, err := this.userByName(req.Name); err == nil {
			return fmt.Errorf("refusing to mutate non-local Darwin user %q (UID %s)", native.Username, native.Uid)
		} else if !isUnknownDarwinUser(err) {
			return fmt.Errorf("cannot verify Darwin user name %q is unused: %w", req.Name, err)
		}
	}
	if req.Uid != nil {
		if native, err := this.userById(req.Uid.String()); err == nil {
			return fmt.Errorf("refusing to mutate non-local Darwin user %q (UID %s)", native.Username, native.Uid)
		} else if !isUnknownDarwinUser(err) {
			return fmt.Errorf("cannot verify Darwin UID %d is unused: %w", *req.Uid, err)
		}
	}
	return nil
}

func (this *DarwinRepository) rejectNonLocalUserNameCollision(name string) error {
	return this.rejectNonLocalUserCollision(&Requirement{Name: name})
}

func (this *DarwinRepository) rejectNonLocalGroupCollision(req *GroupRequirement) error {
	if req.Name != "" {
		if native, err := this.groupByName(req.Name); err == nil {
			return fmt.Errorf("refusing to mutate non-local Darwin group %q (GID %s)", native.Name, native.Gid)
		} else if !isUnknownDarwinGroup(err) {
			return fmt.Errorf("cannot verify Darwin group name %q is unused: %w", req.Name, err)
		}
	}
	if req.Gid != nil {
		if native, err := this.groupById(req.Gid.String()); err == nil {
			return fmt.Errorf("refusing to mutate non-local Darwin group %q (GID %s)", native.Name, native.Gid)
		} else if !isUnknownDarwinGroup(err) {
			return fmt.Errorf("cannot verify Darwin GID %d is unused: %w", *req.Gid, err)
		}
	}
	return nil
}

func (this *DarwinRepository) rejectNonLocalGroupNameCollision(name string) error {
	return this.rejectNonLocalGroupCollision(&GroupRequirement{Name: name})
}

func (this *DarwinRepository) DeleteById(ctx context.Context, id Id, opts *DeleteOpts) error {
	return this.deleteUser(ctx, opts, func(ctx context.Context) (*darwinUserRecord, error) {
		return this.localUserByID(ctx, id)
	}, "", "")
}

func (this *DarwinRepository) DeleteByName(ctx context.Context, name string, opts *DeleteOpts) error {
	return this.deleteUser(ctx, opts, func(ctx context.Context) (*darwinUserRecord, error) {
		return this.localUserByName(ctx, name)
	}, "", "")
}

func (this *DarwinRepository) DeleteByIdentity(ctx context.Context, id Id, name, expectedHomeDir string, opts *DeleteOpts) error {
	return this.deleteUser(ctx, opts, func(ctx context.Context) (*darwinUserRecord, error) {
		return this.localUserByID(ctx, id)
	}, name, expectedHomeDir)
}

func (this *DarwinRepository) DeleteHomeByAbsentIdentity(ctx context.Context, id Id, name, expectedHomeDir string) error {
	if err := this.lockMutation(ctx); err != nil {
		return err
	}
	defer darwinMutationMutex.Unlock()
	if expectedHomeDir == "" {
		return fmt.Errorf("cannot clean up absent Darwin account home without its expected path")
	}
	if _, err := this.userById(id.String()); err == nil {
		return fmt.Errorf("refusing home cleanup: UID %d is no longer absent", id)
	} else if !isUnknownDarwinUser(err) {
		return err
	}
	if _, err := this.userByName(name); err == nil {
		return fmt.Errorf("refusing home cleanup: user name %q is no longer absent", name)
	} else if !isUnknownDarwinUser(err) {
		return err
	}
	home, err := this.prepareDarwinHomeRemoval(ctx, &darwinUserRecord{name: name, uid: id, homeDir: expectedHomeDir})
	if err != nil {
		return err
	}
	defer home.close()
	return home.remove(ctx)
}

func (this *DarwinRepository) deleteUser(ctx context.Context, opts *DeleteOpts, lookup func(context.Context) (*darwinUserRecord, error), expectedName, expectedHome string) (rErr error) {
	if err := this.lockMutation(ctx); err != nil {
		return err
	}
	defer darwinMutationMutex.Unlock()
	record, err := lookup(ctx)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNoSuchUser
	}
	if err := this.verifyDarwinUserBinding(ctx, record); err != nil {
		return err
	}
	if expectedName != "" && record.name != expectedName {
		return fmt.Errorf("account %d changed name", record.uid)
	}
	if opts.IsHomeDir() && expectedName != "" {
		if expectedHome == "" || filepath.Clean(record.homeDir) != filepath.Clean(expectedHome) {
			return fmt.Errorf("account %q changed home directory", record.name)
		}
	}
	var home *darwinOwnedHome
	if opts.IsHomeDir() {
		home, err = this.prepareDarwinHomeRemoval(ctx, record)
		if err != nil {
			return err
		}
		defer home.close()
	}
	if opts.IsKillProcesses() {
		if err := this.killAllDarwinProcesses(ctx, record.uid); err != nil {
			return err
		}
	}
	transaction := &darwinMutation{}
	accountDeleted := false
	defer func() {
		if !accountDeleted {
			rErr = stderrors.Join(rErr, transaction.rollback(ctx))
		}
	}()
	groups, err := this.allLocalGroups(ctx)
	if err != nil {
		return err
	}
	for _, group := range groups {
		if !darwinGroupContainsUser(group, record) {
			continue
		}
		if err := this.mutateDarwinGroupMembership(group, []string{record.name}, record.generatedUID, transaction, func() error {
			return this.editLocalGroupMember(ctx, group.name, record.name, false)
		}); err != nil {
			return err
		}
		updated, err := this.localGroupByName(ctx, group.name)
		if err != nil {
			return err
		}
		if updated == nil || darwinGroupContainsUser(updated, record) {
			return fmt.Errorf("local Darwin group %q still contains user %q after membership removal", group.name, record.name)
		}
	}
	path, _ := darwinRecordPath("Users", record.name)
	if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-delete", path); err != nil {
		return berrors.Newf(berrors.System, "cannot delete local Darwin user %q: %w", record.name, err)
	}
	accountDeleted = true
	if remaining, err := this.localUserByName(ctx, record.name); err != nil {
		return err
	} else if remaining != nil {
		return fmt.Errorf("local Darwin user %q still exists after deletion", record.name)
	}
	if _, err := this.runNative(ctx, darwinDSCacheUtilPath, "-flushcache"); err != nil {
		return fmt.Errorf("cannot flush Darwin account cache after deleting user %q: %w", record.name, err)
	}
	groups, err = this.allLocalGroups(ctx)
	if err != nil {
		return fmt.Errorf("account %q was deleted but group membership cleanup could not be verified: %w", record.name, err)
	}
	var membershipCleanupErr error
	for _, group := range groups {
		if err := this.purgeLocalGroupMembershipValues(ctx, group, record); err != nil {
			membershipCleanupErr = stderrors.Join(membershipCleanupErr, fmt.Errorf("group %q: %w", group.name, err))
		}
	}
	if membershipCleanupErr != nil {
		return fmt.Errorf("account %q was deleted but membership cleanup failed: %w", record.name, membershipCleanupErr)
	}
	if home != nil {
		if err := home.remove(ctx); err != nil {
			return fmt.Errorf("account %q was deleted but home cleanup failed: %w", record.name, err)
		}
	}
	return nil
}

func (this *DarwinRepository) DeleteGroupById(ctx context.Context, id GroupId, opts *DeleteOpts) error {
	return this.deleteGroup(ctx, opts, func(ctx context.Context) (*darwinGroupRecord, error) {
		return this.localGroupByID(ctx, id)
	})
}

func (this *DarwinRepository) DeleteGroupByName(ctx context.Context, name string, opts *DeleteOpts) error {
	return this.deleteGroup(ctx, opts, func(ctx context.Context) (*darwinGroupRecord, error) {
		return this.localGroupByName(ctx, name)
	})
}

func (this *DarwinRepository) deleteGroup(ctx context.Context, _ *DeleteOpts, lookup func(context.Context) (*darwinGroupRecord, error)) error {
	if err := this.lockMutation(ctx); err != nil {
		return err
	}
	defer darwinMutationMutex.Unlock()
	record, err := lookup(ctx)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNoSuchGroup
	}
	if err := this.verifyDarwinGroupBinding(record); err != nil {
		return err
	}
	users, err := this.allLocalUsers(ctx)
	if err != nil {
		return err
	}
	for _, candidate := range users {
		if candidate.gid == record.gid {
			return fmt.Errorf("cannot delete group because it is still used by user %d(%s)", candidate.uid, candidate.name)
		}
	}
	path, _ := darwinRecordPath("Groups", record.name)
	if _, err := this.runNative(ctx, darwinDSCLPath, darwinLocalNode, "-delete", path); err != nil {
		return berrors.Newf(berrors.System, "cannot delete local Darwin group %q: %w", record.name, err)
	}
	if remaining, err := this.localGroupByName(ctx, record.name); err != nil {
		return err
	} else if remaining != nil {
		return fmt.Errorf("local Darwin group %q still exists after deletion", record.name)
	}
	return nil
}

func (this *DarwinRepository) KillProcessesByIdentity(ctx context.Context, id Id, name string) error {
	if err := this.lockMutation(ctx); err != nil {
		return err
	}
	defer darwinMutationMutex.Unlock()
	record, err := this.localUserByID(ctx, id)
	if err != nil {
		return err
	}
	if record == nil {
		return ErrNoSuchUser
	}
	if err := this.verifyDarwinUserBinding(ctx, record); err != nil {
		return err
	}
	if record.name != name {
		return fmt.Errorf("account %d changed name", id)
	}
	return this.killAllDarwinProcesses(ctx, id)
}

// KillProcessesByAbsentIdentity only permits UID-based cleanup while both the
// original name and UID remain absent from the complete account search path.
func (this *DarwinRepository) KillProcessesByAbsentIdentity(ctx context.Context, id Id, name string) error {
	if err := this.lockMutation(ctx); err != nil {
		return err
	}
	defer darwinMutationMutex.Unlock()
	if _, err := this.userById(id.String()); err == nil {
		return fmt.Errorf("refusing process cleanup: UID %d is no longer absent", id)
	} else if !isUnknownDarwinUser(err) {
		return err
	}
	if _, err := this.userByName(name); err == nil {
		return fmt.Errorf("refusing process cleanup: user name %q is no longer absent", name)
	} else if !isUnknownDarwinUser(err) {
		return err
	}
	return this.killAllDarwinProcesses(ctx, id)
}

func (this *DarwinRepository) killAllDarwinProcesses(ctx context.Context, id Id) error {
	list := this.processes
	if list == nil {
		list = process.ProcessesWithContext
	}
	processes, err := list(ctx)
	if err != nil {
		return berrors.Newf(berrors.System, "cannot list processes of Darwin user %d: %w", id, err)
	}
	for _, candidate := range processes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if candidate.Pid == int32(os.Getpid()) {
			continue
		}
		uids, err := candidate.UidsWithContext(ctx)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return berrors.Newf(berrors.System, "cannot inspect process %d: %w", candidate.Pid, err)
		}
		if len(uids) == 0 || uids[0] != uint32(id) {
			continue
		}
		if err := killVerifiedUserProcess(ctx, candidate, uint32(id)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return berrors.Newf(berrors.System, "cannot kill process %d of Darwin user %d: %w", candidate.Pid, id, err)
		}
	}
	return nil
}
