//go:build unix

package user

import (
	"bytes"
	"errors"
	"fmt"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	DefaultRepository Repository = &EtcColonRepository{}

	ErrEtcColonRepositoryUnsupportedRemove error = StringError("etc colon repository does not support removing of files")
	ErrEtcColonRepositoryUnsupportedRename error = StringError("etc colon repository does not support renaming of files")

	DefaultFileSystemSyncThreshold = time.Second * 2
	DefaultAllowBadName            = false
	DefaultAllowBadLine            = true
)

// EtcColonRepository implements Repository based on the /etc/passwd file standard
// commonly used in Unix operating systems (see [Wikipedia article] for more
// information).
//
// This repository does listen to external changes to the underlying files. As a
// consequence this repository always contain the latest data which are created
// by itself or externally. There is a lack defined by FileSystemSyncThreshold to
// ensure that changes are not applied too often.
//
// It is required to call Init before first usage and Close for disposing.
//
// [Wikipedia article]: https://en.wikipedia.org/wiki/Passwd
type EtcColonRepository struct {
	// PasswdFilename defines which file to use for reading the base user
	// information from. If empty DefaultEtcPasswd will be used.
	PasswdFilename string

	// GroupFilename defines which file to use for reading the group
	// information from. If empty DefaultEtcGroup will be used.
	GroupFilename string

	// ShadowFilename defines which file to use for reading the hashed
	// password information of a user from.
	// If empty DefaultEtcShadow will be used.
	ShadowFilename string

	// AllowBadName defines that if bad names of users and groups are allowed
	// within the files.
	//
	// It leads to that also other characters than the default ones are
	// allowed. Usually are only ^[a-z][-a-z0-9]*$ allowed. As nowadays
	// often also . (dots) or @ (ats) are used in usernames, it makes
	// sense to enable them. The majority of the current unix systems are
	// supporting those username, too.
	//
	// If empty DefaultAllowBadName will be used.
	AllowBadName *bool

	// AllowBadLine defines that if malformed lines within the files are
	// allowed and will be preserved.
	//
	// If the repository will neither read nor write those files successfully
	// in those cases. If mainly used to work on existing ones, true is
	// recommended.
	//
	// If empty DefaultAllowBadLine will be used.
	AllowBadLine *bool

	// OnUnhandledAsyncError will be called when in async contexts are errors
	// appearing. By default, those errors are leading to a log message and
	// that the whole application will exit with code 17.
	OnUnhandledAsyncError func(logger log.Logger, err error, detail string)

	// FileSystemSyncThreshold ensures that only external changes are accepted
	// if there are no more new ones within this duration. This prevents that
	// everything is loaded too often. This defaults to
	// DefaultFileSystemSyncThreshold.
	FileSystemSyncThreshold time.Duration

	// Logger will be used to log events to. If empty the log.GetRootLogger()
	// will be used.
	Logger log.Logger

	nameToUser       nameToEtcPasswdRef
	idToUser         idToEtcPasswdRef
	nameToGroup      nameToEtcGroupRef
	idToGroup        idToEtcGroupRef
	usernameToGroups nameToEtcGroupRefs

	handles     etcUnixModifierHandles
	mutex       sync.RWMutex
	reloadTimer *time.Timer
}

// Init will initialize this repository.
func (this *EtcColonRepository) Init() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if this.reloadTimer == nil {
		first := true
		this.reloadTimer = time.AfterFunc(-1, func() {
			// The first load we want to do manually to catch the error directly...
			if first {
				first = false
				return
			}
			if err := this.load(&this.mutex); err != nil {
				this.onUnhandledAsyncError(this.logger(), err, "cannot reload repository")
			}
		})
	}

	if err := this.handles.init(this); err != nil {
		return err
	}

	return this.load(nil) // We do not provider a mutex, because we're already inside a lock
}

// LookupByName implements Repository.LookupByName.
func (this *EtcColonRepository) LookupByName(name string) (*User, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	n2u := this.nameToUser
	if n2u == nil {
		return nil, ErrNoSuchUser
	}

	ref, ok := n2u[name]
	if !ok {
		return nil, ErrNoSuchUser
	}

	return this.refToUser(ref)
}

// LookupById implements Repository.LookupById.
func (this *EtcColonRepository) LookupById(id Id) (*User, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	i2u := this.idToUser
	if i2u == nil {
		return nil, ErrNoSuchUser
	}

	ref, ok := i2u[id]
	if !ok {
		return nil, ErrNoSuchUser
	}

	return this.refToUser(ref)
}

// LookupGroupByName implements Repository.LookupGroupByName.
func (this *EtcColonRepository) LookupGroupByName(name string) (*Group, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	n2g := this.nameToGroup
	if n2g == nil {
		return nil, ErrNoSuchGroup
	}

	ref, ok := n2g[name]
	if !ok {
		return nil, ErrNoSuchGroup
	}

	return this.refToGroup(ref)
}

// LookupGroupById implements Repository.LookupGroupById.
func (this *EtcColonRepository) LookupGroupById(id GroupId) (*Group, error) {
	return this.lookupGroupById(id, this.mutex.RLocker())
}

func (this *EtcColonRepository) lookupGroupById(id GroupId, mutex sync.Locker) (*Group, error) {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	i2g := this.idToGroup
	gr, ok := i2g[id]
	if !ok {
		return nil, ErrNoSuchGroup
	}

	return this.refToGroup(gr)
}

func (this *EtcColonRepository) lookupByRequirement(req *Requirement) *etcPasswdRef {
	if v := req.Name; v != "" {
		n2u := this.nameToUser
		if n2u != nil {
			result, ok := n2u[v]
			if ok {
				return result
			}
		}
	}

	if v := req.Uid; v != nil {
		i2u := this.idToUser
		if i2u != nil {
			result, ok := i2u[*v]
			if ok {
				return result
			}
		}
	}

	return nil
}

func (this *EtcColonRepository) lookupGroupByRequirement(req *GroupRequirement, mutex sync.Locker) *etcGroupRef {
	if mutex != nil {
		this.mutex.RLock()
		defer this.mutex.RUnlock()
	}

	if v := req.Name; v != "" {
		n2g := this.nameToGroup
		if n2g != nil {
			result, ok := n2g[v]
			if ok {
				return result
			}
		}
	}

	if v := req.Gid; v != nil {
		i2g := this.idToGroup
		if i2g != nil {
			result, ok := i2g[*v]
			if ok {
				return result
			}
		}
	}

	return nil
}

func (this *EtcColonRepository) isRequirementFulfilled(req *Requirement, mutex sync.Locker) (*etcPasswdRef, *User, error) {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	existing := this.lookupByRequirement(req)
	if existing == nil {
		return nil, nil, nil
	}

	if !req.doesFulfilRef(existing) {
		return existing, nil, nil
	}

	existingGroup := this.lookupGroupByRequirement(&req.Group, nil)
	if existingGroup == nil {
		return existing, nil, nil
	}
	if !req.Group.doesFulfilRef(existingGroup) {
		return existing, nil, nil
	}
	if existingGroup.gid != existing.gid {
		return existing, nil, nil
	}

	var groupRefs []*etcGroupRef
	if u2gs := this.usernameToGroups; u2gs == nil {
		if vs, ok := u2gs[string(existing.etcPasswdEntry.name)]; ok {
			groupRefs = vs
		}
	}

	if len(req.Groups) != len(groupRefs) {
		return existing, nil, nil
	}

	for _, groupRef := range groupRefs {
		atLeastOneMatches := false
		for _, groupReq := range req.Groups {
			if groupReq.doesFulfilRef(groupRef) {
				atLeastOneMatches = true
				break
			}
		}
		if !atLeastOneMatches {
			return existing, nil, nil
		}
	}

	user, err := this.refToUser(existing)
	return existing, user, err
}

// Ensure implements Ensurer.Ensure.
func (this *EtcColonRepository) Ensure(req *Requirement, opts *EnsureOpts) (*User, error) {
	if req == nil {
		panic("nil user requirement")
	}
	tReq := req.OrDefaults()
	tOpts := opts.OrDefaults()

	var err error
	var result *User
	var existing *etcPasswdRef

	if existing, result, err = this.isRequirementFulfilled(&tReq, this.mutex.RLocker()); err != nil || result != nil {
		return result, err
	}

	if existing == nil && !*tOpts.CreateAllowed {
		return nil, ErrNoSuchUser
	}

	if !*tOpts.ModifyAllowed {
		return nil, ErrUserDoesNotFulfilRequirement
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()

	if existing, result, err = this.isRequirementFulfilled(&tReq, nil); err != nil || result != nil {
		return result, err
	}

	if existing == nil && !*tOpts.CreateAllowed {
		return nil, ErrNoSuchUser
	}

	if !*tOpts.ModifyAllowed {
		return nil, ErrUserDoesNotFulfilRequirement
	}

	_, group, err := this.ensureGroup(&tReq.Group, &tOpts, nil)
	if err != nil {
		return nil, err
	}
	groupRefs, groups, err := this.ensureGroups(&tReq.Groups, &tOpts)
	if err != nil {
		return nil, err
	}

	if existing == nil {
		ref, err := tReq.toEtcPasswdRef(group.Gid, func() (Id, error) {
			result := this.findHighestUid()
			if result < 1000 {
				result = 1000
			}
			return result, nil
		})
		if err != nil {
			return nil, err
		}
		this.handles.passwd.entries = append(this.handles.passwd.entries, etcColonEntry[etcPasswdEntry, *etcPasswdEntry]{
			entry:   ref.etcPasswdEntry,
			rawLine: nil,
		})
		this.handles.shadow.entries = append(this.handles.shadow.entries, etcColonEntry[etcShadowEntry, *etcShadowEntry]{
			entry:   ref.etcShadowEntry,
			rawLine: nil,
		})
		this.nameToUser[string(ref.etcPasswdEntry.name)] = ref
		this.idToUser[Id(ref.etcPasswdEntry.gid)] = ref

		for _, gr := range groupRefs {
			gr.userNames = append(gr.userNames, ref.etcPasswdEntry.name)
		}

		if err := this.handles.save(); err != nil {
			return nil, err
		}

		return this.refAndGroupsToUser(ref, group, &groups), nil
	}

	oldName := existing.etcPasswdEntry.name
	oldUid := existing.etcPasswdEntry.uid

	if err := tReq.updateEtcPasswdRef(existing, group.Gid); err != nil {
		return nil, err
	}

	if bytes.Equal(oldName, existing.etcPasswdEntry.name) {
		delete(this.nameToUser, string(oldName))
		this.nameToUser[string(existing.etcPasswdEntry.name)] = existing
	}
	if oldUid != existing.etcPasswdEntry.uid {
		delete(this.idToUser, Id(oldUid))
		this.idToUser[Id(existing.etcPasswdEntry.uid)] = existing
	}

	notAlreadyHandledGroupRefs := map[uint32]*etcGroupRef{}
	if vs, ok := this.usernameToGroups[string(existing.etcPasswdEntry.name)]; ok {
		notAlreadyHandledGroupRefs = make(map[uint32]*etcGroupRef, len(vs))
		for _, v := range vs {
			notAlreadyHandledGroupRefs[v.gid] = v
		}
	}
	for _, gr := range groupRefs {
		delete(notAlreadyHandledGroupRefs, gr.gid)
		gr.etcGroupEntry.addUniqueUserName(existing.etcPasswdEntry.name)
	}
	for _, gr := range notAlreadyHandledGroupRefs {
		gr.etcGroupEntry.removeUserName(existing.etcPasswdEntry.name)
	}
	this.usernameToGroups[string(existing.etcPasswdEntry.name)] = groupRefs

	if err := this.handles.save(); err != nil {
		return nil, err
	}

	return this.refAndGroupsToUser(existing, group, &groups), nil
}

// EnsureGroup implements Ensurer.EnsureGroup.
func (this *EtcColonRepository) EnsureGroup(req *GroupRequirement, opts *EnsureOpts) (*Group, error) {
	if req == nil {
		panic("nil group requirement")
	}
	tOpts := opts.OrDefaults()

	existing := this.lookupGroupByRequirement(req, this.mutex.RLocker())
	if existing != nil && req.doesFulfilRef(existing) {
		return this.refToGroup(existing)
	}

	if existing == nil && !*tOpts.CreateAllowed {
		return nil, ErrNoSuchGroup
	}

	if !*tOpts.ModifyAllowed {
		return nil, ErrGroupDoesNotFulfilRequirement
	}

	_, result, err := this.ensureGroup(req, &tOpts, &this.mutex)
	return result, err
}

func (this *EtcColonRepository) ensureGroup(req *GroupRequirement, opts *EnsureOpts, mutex sync.Locker) (*etcGroupRef, *Group, error) {
	if req == nil {
		panic("nil group requirement")
	}
	tOpts := opts.OrDefaults()

	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	existing := this.lookupGroupByRequirement(req, nil)
	if existing != nil && req.doesFulfilRef(existing) {
		group, err := this.refToGroup(existing)
		return existing, group, err
	}

	if existing == nil && !*tOpts.CreateAllowed {
		return nil, nil, ErrNoSuchGroup
	}

	if !*tOpts.ModifyAllowed {
		return existing, nil, ErrGroupDoesNotFulfilRequirement
	}

	if existing == nil {
		ref, err := req.toEtcGroupRef(func() (GroupId, error) {
			result := this.findHighestGid()
			if result < 1000 {
				result = 1000
			}
			return result, nil
		})
		if err != nil {
			return nil, nil, err
		}
		this.handles.group.entries = append(this.handles.group.entries, etcColonEntry[etcGroupEntry, *etcGroupEntry]{
			entry:   ref.etcGroupEntry,
			rawLine: nil,
		})
		this.nameToGroup[string(ref.etcGroupEntry.name)] = ref
		this.idToGroup[GroupId(ref.etcGroupEntry.gid)] = ref
		result, err := this.refToGroup(ref)
		return ref, result, err
	}

	oldName := existing.etcGroupEntry.name
	oldGid := existing.etcGroupEntry.gid
	if err := req.updateEtcGroupRef(existing); err != nil {
		return existing, nil, err
	}

	if !bytes.Equal(oldName, existing.etcGroupEntry.name) {
		delete(this.nameToGroup, string(oldName))
		this.nameToGroup[string(existing.etcGroupEntry.name)] = existing
	}
	if oldGid != existing.etcGroupEntry.gid {
		delete(this.idToGroup, GroupId(existing.etcGroupEntry.gid))
		this.idToGroup[GroupId(existing.etcGroupEntry.gid)] = existing
	}

	result, err := this.refToGroup(existing)
	return existing, result, err
}

func (this *EtcColonRepository) ensureGroups(reqs *GroupRequirements, opts *EnsureOpts) ([]*etcGroupRef, Groups, error) {
	if reqs == nil {
		panic("nil group requirements")
	}
	tOpts := opts.OrDefaults()

	refs := make([]*etcGroupRef, len(*reqs))
	result := make(Groups, len(*reqs))
	for i, req := range *reqs {
		ref, v, err := this.ensureGroup(&req, &tOpts, nil)
		if err != nil {
			return nil, nil, err
		}
		refs[i] = ref
		result[i] = *v
	}

	return refs, result, nil
}

func (this *EtcColonRepository) findHighestGid() GroupId {
	var result GroupId
	for _, v := range this.handles.group.entries {
		actual := GroupId(v.entry.gid)
		if actual > result {
			result = actual
		}
	}

	return result
}

func (this *EtcColonRepository) findHighestUid() Id {
	var result Id
	for _, v := range this.handles.passwd.entries {
		actual := Id(v.entry.uid)
		if actual > result {
			result = actual
		}
	}

	return result
}

func (this *EtcColonRepository) refToUser(ref *etcPasswdRef) (*User, error) {
	fail := func(err error) (*User, error) {
		return nil, fmt.Errorf("user %d(%s): %w", ref.etcPasswdEntry.uid, string(ref.etcPasswdEntry.name), err)
	}

	group, err := this.lookupGroupById(GroupId(ref.etcPasswdEntry.gid), nil)
	if errors.Is(err, ErrNoSuchGroup) {
		return nil, fmt.Errorf("user %d(%s) references group %d which does not exist", ref.etcPasswdEntry.uid, string(ref.etcPasswdEntry.name), ref.etcPasswdEntry.gid)
	}
	if err != nil {
		return fail(err)
	}

	var groups Groups
	if u2gs := this.usernameToGroups; u2gs != nil {
		if gs, ok := u2gs[string(ref.etcPasswdEntry.name)]; ok {
			groups = make([]Group, len(gs))
			for i, g := range gs {
				group, err := this.lookupGroupById(GroupId(g.gid), nil)
				if err != nil {
					return fail(err)
				}
				groups[i] = *group
			}
		}
	}

	return this.refAndGroupsToUser(ref, group, &groups), nil
}

func (this *EtcColonRepository) refAndGroupsToUser(ref *etcPasswdRef, group *Group, groups *Groups) *User {
	return &User{
		strings.Clone(string(ref.etcPasswdEntry.name)),
		strings.Clone(string(ref.etcPasswdEntry.geocs)),
		Id(ref.etcPasswdEntry.uid),
		*group,
		*groups,
		strings.Clone(string(ref.etcPasswdEntry.shell)),
		strings.Clone(string(ref.etcPasswdEntry.homeDir)),
	}
}

func (this *EtcColonRepository) refToGroup(ref *etcGroupRef) (*Group, error) {
	return &Group{
		GroupId(ref.gid),
		strings.Clone(string(ref.name)),
	}, nil
}

// Close disposes this repository after usage.
func (this *EtcColonRepository) Close() error {
	return this.handles.close(&this.mutex)
}

func (this *EtcColonRepository) onUnhandledAsyncError(logger log.Logger, err error, detail string) {
	if f := this.OnUnhandledAsyncError; f != nil {
		f(logger, err, detail)
		return
	}

	canAddErrIfPresent := true
	msgPrefix := detail

	if msgPrefix == "" {
		if sErr, ok := err.(StringError); ok {
			msgPrefix = string(sErr)
			canAddErrIfPresent = false
		} else {
			msgPrefix = "unknown error"
		}
	}

	if canAddErrIfPresent && err != nil {
		logger = logger.WithError(err)
	}

	logger.Fatal(msgPrefix + "; will exit now to and hope for a restart of this service to reset the state (exit code 17)")
	os.Exit(17)
}

func (this *EtcColonRepository) scheduleReload(l log.Logger) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	l.Debug("schedule reload of repository")

	this.reloadTimer.Stop()
	if v := this.FileSystemSyncThreshold; v != 0 {
		this.reloadTimer.Reset(v)
	} else {
		this.reloadTimer.Reset(DefaultFileSystemSyncThreshold)
	}
}

func (this *EtcColonRepository) load(mutex sync.Locker) error {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	l := this.logger()

	start := time.Now()
	if l.IsDebugEnabled() {
		l.Debug("load user repository...")
	}

	err := this.handles.load() // we do not add the mutex again, because we're already in lock
	if err != nil {
		return err
	}

	nameToGroup, idToGroup, usernameToGroups, err := this.loadGroupsRefs()
	if err != nil {
		return fmt.Errorf("cannot load group entries: %w", err)
	}

	usernameToShadow, err := this.loadShadowsRefs()
	if err != nil {
		return fmt.Errorf("cannot load shadow entries: %w", err)
	}

	nameToUser, idToUser, err := this.loadUsersRefs(usernameToShadow)
	if err != nil {
		return fmt.Errorf("cannot load user entries: %w", err)
	}

	this.idToUser = idToUser
	this.nameToUser = nameToUser
	this.idToGroup = idToGroup
	this.nameToGroup = nameToGroup
	this.usernameToGroups = usernameToGroups

	lw := l.With("duration", fields.LazyFunc(func() any { return time.Since(start).Truncate(time.Microsecond).String() }))
	if l.IsDebugEnabled() {
		lw.Info("load user repository... DONE!")
	} else {
		lw.Info("user repository loaded")
	}

	return nil
}

func (this *EtcColonRepository) loadGroupsRefs() (nameToEtcGroupRef, idToEtcGroupRef, nameToEtcGroupRefs, error) {
	nameToGroup := make(nameToEtcGroupRef, len(this.handles.group.entries))
	idToGroup := make(idToEtcGroupRef, len(this.handles.group.entries))
	usernameToGroup := nameToEtcGroupRefs{}

	for _, e := range this.handles.group.entries {
		if e.entry != nil {
			ref := etcGroupRef{e.entry}
			nameToGroup[string(e.entry.name)] = &ref
			idToGroup[GroupId(e.entry.gid)] = &ref
			for _, un := range ref.userNames {
				usernameToGroup[string(un)] = append(usernameToGroup[string(un)], &ref)
			}
		}
	}

	return nameToGroup, idToGroup, usernameToGroup, nil
}

func (this *EtcColonRepository) loadShadowsRefs() (map[string]*etcShadowEntry, error) {
	nameToShadow := make(map[string]*etcShadowEntry, len(this.handles.shadow.entries))

	for _, e := range this.handles.shadow.entries {
		if e.entry != nil {
			nameToShadow[string(e.entry.name)] = e.entry
		}
	}

	return nameToShadow, nil
}

func (this *EtcColonRepository) loadUsersRefs(usernameToShadow map[string]*etcShadowEntry) (nameToEtcPasswdRef, idToEtcPasswdRef, error) {
	nameToUser := make(nameToEtcPasswdRef, len(this.handles.passwd.entries))
	idToUser := make(idToEtcPasswdRef, len(this.handles.passwd.entries))

	for _, e := range this.handles.passwd.entries {
		if e.entry != nil {
			shadow := usernameToShadow[string(e.entry.name)]

			ref := etcPasswdRef{e.entry, shadow}

			nameToUser[string(e.entry.name)] = &ref
			idToUser[Id(e.entry.uid)] = &ref
		}
	}

	return nameToUser, idToUser, nil
}

func (this *EtcColonRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetRootLogger()
}

func (this *EtcColonRepository) getAllowBadName() bool {
	if v := this.AllowBadName; v != nil {
		return *v
	}
	//goland:noinspection GoBoolExpressions
	return DefaultAllowBadName
}

func (this *EtcColonRepository) getAllowBadLine() bool {
	if v := this.AllowBadLine; v != nil {
		return *v
	}
	//goland:noinspection GoBoolExpressions
	return DefaultAllowBadLine
}

type etcUnixModifierHandles struct {
	passwd etcUnixModifierFileHandle[etcPasswdEntry, *etcPasswdEntry]
	group  etcUnixModifierFileHandle[etcGroupEntry, *etcGroupEntry]
	shadow etcUnixModifierFileHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *etcUnixModifierHandles) init(owner *EtcColonRepository) error {
	success := false
	defer func() {
		if !success {
			_ = this.close(nil)
		}
	}()

	if err := this.passwd.init(owner.PasswdFilename, DefaultEtcPasswd, etcPasswdColons, owner); err != nil {
		return err
	}
	if err := this.group.init(owner.GroupFilename, DefaultEtcGroup, etcGroupColons, owner); err != nil {
		return err
	}
	if err := this.shadow.init(owner.ShadowFilename, DefaultEtcShadow, etcShadowColons, owner); err != nil {
		return err
	}

	success = true
	return nil
}

func (this *etcUnixModifierHandles) load() error {
	if err := this.passwd.load(); err != nil {
		return err
	}
	if err := this.group.load(); err != nil {
		return err
	}
	if err := this.shadow.load(); err != nil {
		return err
	}

	return nil
}

func (this *etcUnixModifierHandles) save() error {
	if err := this.passwd.save(); err != nil {
		return err
	}
	if err := this.group.save(); err != nil {
		return err
	}
	if err := this.shadow.save(); err != nil {
		return err
	}

	return nil
}

func (this *etcUnixModifierHandles) close(mutex sync.Locker) (rErr error) {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	defer func() {
		if err := this.passwd.close(); err != nil && rErr == nil {
			rErr = err
		}
	}()
	defer func() {
		if err := this.group.close(); err != nil && rErr == nil {
			rErr = err
		}
	}()
	defer func() {
		if err := this.shadow.close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return nil
}

type etcUnixModifierFileHandle[T any, PT etcColonEntryValue[T]] struct {
	owner *EtcColonRepository

	fn             string
	numberOfColons int

	watcher       *fsnotify.Watcher
	entries       etcColonEntries[T, PT]
	numberOfReads uint64
}

func (this *etcUnixModifierFileHandle[T, PT]) init(fn, defFn string, numberOfColons int, owner *EtcColonRepository) error {
	if this.watcher != nil {
		return nil
	}

	this.owner = owner
	this.fn = fn
	if this.fn == "" {
		this.fn = defFn
	}
	this.numberOfColons = numberOfColons

	success := false
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot initialize file watcher for %q: %w", this.fn, err)
	}
	defer func() {
		if !success {
			_ = watcher.Close()
		}
	}()
	this.watcher = watcher
	defer func() {
		if !success {
			this.watcher = nil
		}
	}()

	go this.watchForChanges(watcher)

	if err := watcher.Add(this.fn); err != nil {
		return fmt.Errorf("cannot watch for filesystem changes of %q: %w", this.fn, err)
	}

	success = true
	return nil
}

func (this *etcUnixModifierFileHandle[T, PT]) watchForChanges(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			l := this.owner.logger().
				With("op", event.Op).
				With("file", this.fn)

			if event.Has(fsnotify.Remove) {
				// TODO! Add handling of remove event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRemove, "")
			} else if event.Has(fsnotify.Rename) {
				// TODO! Add handling of rename event ... although this should be really not normal behavior.
				this.owner.onUnhandledAsyncError(l, ErrEtcColonRepositoryUnsupportedRename, "")
			} else if event.Has(fsnotify.Write) {
				this.owner.scheduleReload(l)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			l := this.owner.logger().
				With("file", this.fn)
			this.owner.onUnhandledAsyncError(l, err, "error while handling file watcher events")
		}
	}
}

func (this *etcUnixModifierFileHandle[T, PT]) load() (rErr error) {
	if this.fn == "" || this.watcher == nil {
		return fmt.Errorf("was not initialized")
	}

	f, err := this.openFile(false)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	if err := this.entries.decode(this.numberOfColons, this.owner.getAllowBadName(), this.owner.getAllowBadLine(), f); err != nil {
		return err
	}

	this.numberOfReads++
	return nil
}

func (this *etcUnixModifierFileHandle[T, PT]) openFile(write bool) (*os.File, error) {
	fm := os.O_RDONLY
	lm := syscall.LOCK_SH
	if write {
		fm = os.O_WRONLY | os.O_TRUNC | os.O_CREATE
		lm = syscall.LOCK_EX
	}
	success := false

	f, err := os.OpenFile(this.fn, fm, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", this.fn, err)
	}
	defer func() {
		if !success {
			_ = f.Close()
		}
	}()

	if err := this.lockFile(f, lm); err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			_ = this.lockFile(f, syscall.LOCK_UN)
		}
	}()

	success = true
	return f, nil
}

func (this *etcUnixModifierFileHandle[T, PT]) closeFile(f *os.File) (rErr error) {
	if f == nil {
		return nil
	}

	defer func() {
		if err := f.Close(); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return this.lockFile(f, syscall.LOCK_UN)
}

func (this *etcUnixModifierFileHandle[T, PT]) lockFile(which *os.File, how int) error {
	done := false
	doneErrChan := make(chan error, 1)
	defer close(doneErrChan)

	go func(fd, how int) {
		for {
			err := syscall.Flock(fd, how)

			//goland:noinspection GoDirectComparisonOfErrors
			if err == syscall.EINTR {
				if done {
					return
				}
				continue
			}
			doneErrChan <- err
			return
		}
	}(int(which.Fd()), how)

	fail := func(err error) error {
		if err == nil {
			return nil
		}
		var op string
		switch how {
		case syscall.LOCK_EX:
			op = "lock file for write"
		case syscall.LOCK_UN:
			op = "unlock file"
		default:
			op = "lock file for read"
		}
		return fmt.Errorf("cannot %s %q: %w", op, which.Name(), err)
	}
	select {
	case doneErr := <-doneErrChan:
		return fail(doneErr)
	}
}

func (this *etcUnixModifierFileHandle[T, PT]) save() (rErr error) {
	f, err := this.openFile(true)
	if err != nil {
		return err
	}
	defer func() {
		if err := this.closeFile(f); err != nil && rErr == nil {
			rErr = err
		}
	}()

	return this.entries.encode(this.owner.getAllowBadName(), f)
}

func (this *etcUnixModifierFileHandle[T, PT]) close() error {
	if watcher := this.watcher; watcher != nil {
		defer func() {
			this.watcher = nil
		}()
		if err := watcher.Close(); err != nil {
			return err
		}
	}

	return nil
}
