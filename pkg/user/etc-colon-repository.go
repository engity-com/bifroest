//go:build unix

package user

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/fsnotify/fsnotify"
	"github.com/otiai10/copy"
	"github.com/shirou/gopsutil/process"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	DefaultFileSystemSyncThreshold = time.Second * 2
	DefaultCreateFilesIfAbsent     = false
	DefaultAllowBadName            = true
	DefaultAllowBadLine            = true
)

func init() {
	DefaultRepositoryProvider = &SharedRepositoryProvider[*EtcColonRepository]{V: &EtcColonRepository{}}
}

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

	// CreateFilesIfAbsent tells the repository to create the related files if
	// they do not exist. This only makes in very few amount of cases really
	// sense; so: You should now what you're doing.
	//
	// If empty DefaultCreateFilesIfAbsent will be used.
	CreateFilesIfAbsent *bool

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

	// Logger will be used to log events to. If empty the
	// log.GetLogger("user-repository") will be used.
	Logger log.Logger

	nameToUser       nameToEtcPasswdRef
	idToUser         idToEtcPasswdRef
	nameToGroup      nameToEtcGroupRef
	idToGroup        idToEtcGroupRef
	usernameToGroups nameToEtcGroupRefs

	watcher *fsnotify.Watcher

	handles     etcColonRepositoryHandles
	mutex       sync.RWMutex
	reloadTimer *time.Timer
}

// Init will initialize this repository.
func (this *EtcColonRepository) Init(ctx context.Context) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if this.watcher != nil {
		return nil
	}

	success := false
	{
		var firstRunDone atomic.Bool
		this.reloadTimer = time.AfterFunc(-1, func() {
			// The first load we want to do manually to catch the error directly...
			if firstRunDone.CompareAndSwap(false, true) {
				return
			}

			this.onReloadTimer()
		})
	}

	if err := this.handles.init(this); err != nil {
		return err
	}
	defer common.DoOnFailureIgnore(&success, this.handles.close)

	if err := this.load(ctx); err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("cannot initialize file watcher: %w", err)
	}
	defer common.DoOnFailureIgnore(&success, watcher.Close)

	go this.watchForChanges(watcher)

	for v := range this.handles.getDirectories() {
		this.logger().With("directory", v).Debug("watching changes within directory")
		if err := watcher.Add(v); err != nil {
			return err
		}
	}

	this.watcher = watcher
	success = true
	return nil
}

// LookupByName implements Repository.LookupByName.
func (this *EtcColonRepository) LookupByName(ctx context.Context, name string) (*User, error) {
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

	return this.refToUser(ctx, ref)
}

// LookupById implements Repository.LookupById.
func (this *EtcColonRepository) LookupById(ctx context.Context, id Id) (*User, error) {
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

	return this.refToUser(ctx, ref)
}

// LookupGroupByName implements Repository.LookupGroupByName.
func (this *EtcColonRepository) LookupGroupByName(_ context.Context, name string) (*Group, error) {
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

	return this.refToGroup(ref), nil
}

// LookupGroupById implements Repository.LookupGroupById.
func (this *EtcColonRepository) LookupGroupById(ctx context.Context, id GroupId) (*Group, error) {
	result := this.lookupGroupById(ctx, id, this.mutex.RLocker())
	if result == nil {
		return nil, ErrNoSuchGroup
	}
	return result, nil
}

func (this *EtcColonRepository) lookupGroupById(_ context.Context, id GroupId, mutex sync.Locker) *Group {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	i2g := this.idToGroup
	gr, ok := i2g[id]
	if !ok {
		return nil
	}

	return this.refToGroup(gr)
}

func (this *EtcColonRepository) lookupByRequirement(_ context.Context, req *Requirement) *etcPasswdRef {
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

func (this *EtcColonRepository) lookupGroupByRequirement(_ context.Context, req *GroupRequirement, mutex sync.Locker) *etcGroupRef {
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

func (this *EtcColonRepository) isRequirementFulfilled(ctx context.Context, req *Requirement, mutex sync.Locker) (*etcPasswdRef, *User, error) {
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}

	existing := this.lookupByRequirement(ctx, req)
	if existing == nil {
		return nil, nil, nil
	}

	if !req.doesFulfilRef(existing) {
		return existing, nil, nil
	}

	existingGroup := this.lookupGroupByRequirement(ctx, &req.Group, nil)
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
	if u2gs := this.usernameToGroups; u2gs != nil {
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

	user, err := this.refToUser(ctx, existing)
	return existing, user, err
}

func (this *EtcColonRepository) ensurePreChecks(ctx context.Context, req *Requirement, opts *EnsureOpts, mutex sync.Locker) (existing *etcPasswdRef, user *User, _ EnsureResult, err error) {
	if existing, user, err = this.isRequirementFulfilled(ctx, req, mutex); err != nil {
		return nil, nil, EnsureResultError, err
	} else if user != nil {
		return nil, user, EnsureResultUnchanged, nil
	}

	if existing == nil && !opts.IsCreateAllowed() {
		return nil, nil, EnsureResultError, ErrNoSuchUser
	}

	if !opts.IsModifyAllowed() {
		return nil, nil, EnsureResultError, ErrUserDoesNotFulfilRequirement
	}

	return existing, user, EnsureResultUnknown, nil
}

// Ensure implements Ensurer.Ensure.
func (this *EtcColonRepository) Ensure(ctx context.Context, req *Requirement, opts *EnsureOpts) (_ *User, _ EnsureResult, rErr error) {
	if req == nil {
		panic("nil user requirement")
	}
	tReq := req.OrDefaults()

	_, user, pResult, err := this.ensurePreChecks(ctx, &tReq, opts, this.mutex.RLocker())
	if err != nil || pResult != EnsureResultUnknown {
		return user, pResult, err
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()

	f, err := this.openAndLoad(true, true)
	if err != nil {
		return nil, EnsureResultError, err
	}
	defer common.KeepError(&rErr, f.close)

	var existing *etcPasswdRef
	existing, user, pResult, err = this.ensurePreChecks(ctx, &tReq, opts, nil)
	if err != nil || pResult != EnsureResultUnknown {
		return user, pResult, err
	}

	_, group, _, err := this.ensureGroup(ctx, &tReq, &tReq.Group, opts)
	if err != nil {
		return nil, EnsureResultError, err
	}

	groupRefs, groups, err := this.ensureGroups(ctx, &tReq.Groups, opts)
	if err != nil {
		return nil, EnsureResultError, err
	}

	if existing == nil {
		ref := tReq.toEtcPasswdRef(group.Gid, func() Id {
			result := this.findHighestUid(ctx)
			if result < 1000 {
				return 1000
			}
			result++
			if result == 65534 {
				// Yeah... we never want to return 65534, because it is nobody.
				// See: https://wiki.ubuntu.com/nobody
				result++
			}
			return result
		})
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

		if err := f.save(); err != nil {
			return nil, EnsureResultError, err
		}

		if homeDir := ref.homeDir; len(homeDir) > 0 && opts.IsHomeDir() {
			if err := this.createHomeDir(ctx, ref, req.Skel, string(homeDir), opts.GetOnHomeDirExist()); err != nil {
				return nil, EnsureResultError, err
			}
		}

		this.loggerForRef(ref).Info("user created")

		return this.refAndGroupsToUser(ref, group, &groups), EnsureResultCreated, nil
	}

	oldName := existing.etcPasswdEntry.name
	oldUid := existing.etcPasswdEntry.uid
	oldHomeDir := existing.etcPasswdEntry.homeDir

	if err := tReq.updateEtcPasswdRef(existing, group.Gid); err != nil {
		return nil, EnsureResultError, err
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
	if !bytes.Equal(oldName, existing.etcPasswdEntry.name) {
		if vs, ok := this.usernameToGroups[string(oldName)]; ok {
			for _, v := range vs {
				v.etcGroupEntry.removeUserName(oldName)
			}
		}
		delete(this.usernameToGroups, string(oldName))
	}
	for _, gr := range groupRefs {
		delete(notAlreadyHandledGroupRefs, gr.gid)
		gr.etcGroupEntry.addUniqueUserName(existing.etcPasswdEntry.name)
	}
	for _, gr := range notAlreadyHandledGroupRefs {
		gr.etcGroupEntry.removeUserName(existing.etcPasswdEntry.name)
	}
	this.usernameToGroups[string(existing.etcPasswdEntry.name)] = groupRefs

	if err := f.save(); err != nil {
		return nil, EnsureResultError, err
	}

	if !bytes.Equal(oldHomeDir, existing.etcPasswdEntry.homeDir) && opts.IsHomeDir() {
		if err := this.moveHomeDir(ctx, existing, string(oldHomeDir), string(existing.etcPasswdEntry.homeDir), opts.GetOnHomeDirExist()); err != nil {
			return nil, EnsureResultError, err
		}
	}

	this.loggerForRef(existing).Info("user updated")

	return this.refAndGroupsToUser(existing, group, &groups), EnsureResultModified, nil
}

func (this *EtcColonRepository) createHomeDir(ctx context.Context, ref *etcPasswdRef, skel, homeDir string, ohde EnsureOnHomeDirExist) error {
	fail := func(err error) error {
		return errors.Newf(errors.System, "cannot create user's %v home directory (%s): %w", ref, homeDir, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	l := this.loggerForRef(ref).
		With("homeDir", homeDir).
		With("skel", skel)

	canContinue, canLog, err := this.existingHomeDirCheck(ctx, l, ref, homeDir, ohde)
	if err != nil {
		return fail(err)
	} else if !canContinue {
		return nil
	}

	if err := os.MkdirAll(homeDir, 0700); err != nil {
		return fail(err)
	}
	if err := etcColonRepositoryChownFunc(homeDir, int(ref.uid), int(ref.gid)); err != nil {
		return fail(err)
	}

	if skel != "" {
		control := func(srcinfo os.FileInfo, dest string) (func(*error), error) {
			orig, err := copy.PerservePermission(srcinfo, dest)
			return func(reported *error) {
				orig(reported)
				if *reported == nil {
					*reported = etcColonRepositoryChownFunc(dest, int(ref.uid), int(ref.gid))
				}
			}, err
		}
		if err := copy.Copy(skel, homeDir, copy.Options{
			PreserveTimes:     true,
			Specials:          true,
			PermissionControl: *(*copy.PermissionControlFunc)(unsafe.Pointer(&control)),
		}); err != nil {
			return failf("cannot copy skel directory %q: %w", skel, err)
		}
	}

	if canLog {
		l.Info("user's home directory created")
	}

	return nil
}

func (this *EtcColonRepository) moveHomeDir(ctx context.Context, ref *etcPasswdRef, oldHomeDir string, newHomeDir string, ohde EnsureOnHomeDirExist) error {
	fail := func(err error) error {
		return errors.Newf(errors.System, "cannot move user's %v home directory from %q to %q: %w", ref, oldHomeDir, newHomeDir, err)
	}

	l := this.loggerForRef(ref).
		With("new", newHomeDir).
		With("old", oldHomeDir)

	canContinue, canLog, err := this.existingHomeDirCheck(ctx, l, ref, newHomeDir, ohde)
	if err != nil {
		return fail(err)
	} else if !canContinue {
		return nil
	}

	if _, err := os.Stat(oldHomeDir); sys.IsNotExist(err) {
		// This is ok, we do simply nothing...
		return nil
	} else if err != nil {
		return fail(err)
	}

	_ = os.MkdirAll(filepath.Dir(newHomeDir), 0700)

	if err := os.Rename(oldHomeDir, newHomeDir); err != nil {
		return fail(err)
	}
	if err := this.chownRecursively(newHomeDir, ref.uid, ref.gid); err != nil {
		return fail(err)
	}

	if canLog {
		l.Info("user's home directory moved")
	}

	return nil
}

func (this *EtcColonRepository) existingHomeDirCheck(ctx context.Context, logger log.Logger, ref *etcPasswdRef, homeDir string, ohde EnsureOnHomeDirExist) (canContinue, canLog bool, _ error) {
	fi, err := os.Stat(homeDir)
	if sys.IsNotExist(err) {
		return true, true, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("cannot check for existing home dir (%s): %w", homeDir, err)
	}

	if ohde == EnsureOnHomeDirExistTakeover {
		if !fi.IsDir() {
			return false, false, fmt.Errorf("home directory (%s) exists and should be taken over; but it is a file", homeDir)
		}

		logger.Info("directory already exist; it will be taken over")
		if err := this.chownRecursively(homeDir, ref.uid, ref.gid); err != nil {
			return false, false, fmt.Errorf("cannot chown recursively existing home dir (%s) to take it over: %w", homeDir, err)
		}
		return false, false, nil
	}

	if ohde == EnsureOnHomeDirExistOverwrite {
		logger.Info("directory already exist; it will be overwritten")
		if err := os.RemoveAll(homeDir); err != nil {
			return false, false, fmt.Errorf("home directory (%s) exists and should be overwritten, but it cannot be deleted: %w", homeDir, err)
		}
		return true, false, nil
	}

	return false, false, fmt.Errorf("home directory (%s) already exists", homeDir)
}

func (this *EtcColonRepository) chownRecursively(fn string, uid, gid uint32) error {
	return filepath.Walk(fn, func(path string, fi fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if err := etcColonRepositoryChownFunc(path, int(uid), int(gid)); err != nil {
			return err
		}

		return nil
	})
}

// DeleteById implements Repository.DeleteById.
func (this *EtcColonRepository) DeleteById(ctx context.Context, id Id, opts *DeleteOpts) (rErr error) {
	return this.deleteRef(ctx, opts, func() (*etcPasswdRef, error) {
		i2u := this.idToUser
		if i2u == nil {
			return nil, ErrNoSuchUser
		}

		ref, ok := i2u[id]
		if !ok {
			return nil, ErrNoSuchUser
		}

		return ref, nil
	})
}

// DeleteByName implements Repository.DeleteByName.
func (this *EtcColonRepository) DeleteByName(ctx context.Context, name string, opts *DeleteOpts) (rErr error) {
	return this.deleteRef(ctx, opts, func() (*etcPasswdRef, error) {
		n2u := this.nameToUser
		if n2u == nil {
			return nil, ErrNoSuchUser
		}

		ref, ok := n2u[name]
		if !ok {
			return nil, ErrNoSuchUser
		}

		return ref, nil
	})
}

func (this *EtcColonRepository) deleteRef(ctx context.Context, opts *DeleteOpts, selector func() (*etcPasswdRef, error)) (rErr error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	f, err := this.openAndLoad(true, true)
	if err != nil {
		return err
	}
	defer common.KeepError(&rErr, f.close)

	ref, err := selector()
	if err != nil {
		return err
	}

	delete(this.nameToUser, string(ref.etcPasswdEntry.name))
	delete(this.idToUser, Id(ref.etcPasswdEntry.uid))

	for _, gRef := range this.usernameToGroups[string(ref.etcPasswdEntry.name)] {
		gRef.removeUserName(ref.etcPasswdEntry.name)
	}
	delete(this.usernameToGroups, string(ref.etcPasswdEntry.name))

	this.handles.passwd.entries = slices.DeleteFunc(this.handles.passwd.entries, func(candidate etcColonEntry[etcPasswdEntry, *etcPasswdEntry]) bool {
		if candidate.entry == nil {
			return false
		}
		return candidate.entry.uid == ref.etcPasswdEntry.uid
	})
	this.handles.shadow.entries = slices.DeleteFunc(this.handles.shadow.entries, func(candidate etcColonEntry[etcShadowEntry, *etcShadowEntry]) bool {
		if candidate.entry == nil {
			return false
		}
		return bytes.Equal(candidate.entry.name, ref.etcShadowEntry.name)
	})

	if err := f.save(); err != nil {
		return err
	}

	if opts.IsKillProcesses() {
		if err := this.killAllOf(ctx, ref.uid); err != nil {
			return err
		}
	}

	if opts.IsHomeDir() {
		if err := os.RemoveAll(string(ref.homeDir)); sys.IsNotExist(err) {
			// Ok...
		} else if err != nil {
			return err
		}
	}

	this.loggerForRef(ref).Info("user deleted")

	return nil
}

// ValidatePasswordById implements Repository.ValidatePasswordById.
func (this *EtcColonRepository) ValidatePasswordById(ctx context.Context, id Id, pass string) (bool, error) {
	return this.validatePasswordRef(ctx, pass, func() (*etcPasswdRef, error) {
		i2u := this.idToUser
		if i2u == nil {
			return nil, ErrNoSuchUser
		}

		ref, ok := i2u[id]
		if !ok {
			return nil, ErrNoSuchUser
		}

		return ref, nil
	})
}

// ValidatePasswordByName implements Repository.ValidatePasswordByName.
func (this *EtcColonRepository) ValidatePasswordByName(ctx context.Context, name string, pass string) (bool, error) {
	return this.validatePasswordRef(ctx, pass, func() (*etcPasswdRef, error) {
		n2u := this.nameToUser
		if n2u == nil {
			return nil, ErrNoSuchUser
		}

		ref, ok := n2u[name]
		if !ok {
			return nil, ErrNoSuchUser
		}

		return ref, nil
	})
}

func (this *EtcColonRepository) validatePasswordRef(_ context.Context, pass string, selector func() (*etcPasswdRef, error)) (_ bool, rErr error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	ref, err := selector()
	if err != nil {
		return false, err
	}

	return ref.validatePassword(pass)
}

// DeleteGroupById implements Repository.DeleteGroupById.
func (this *EtcColonRepository) DeleteGroupById(ctx context.Context, id GroupId, opts *DeleteOpts) (rErr error) {
	return this.deleteGroupRef(ctx, opts, func() (*etcGroupRef, error) {
		i2g := this.idToGroup
		if i2g == nil {
			return nil, ErrNoSuchGroup
		}

		ref, ok := i2g[id]
		if !ok {
			return nil, ErrNoSuchGroup
		}

		return ref, nil
	})
}

// DeleteGroupByName implements Repository.DeleteGroupByName.
func (this *EtcColonRepository) DeleteGroupByName(ctx context.Context, name string, opts *DeleteOpts) (rErr error) {
	return this.deleteGroupRef(ctx, opts, func() (*etcGroupRef, error) {
		n2g := this.nameToGroup
		if n2g == nil {
			return nil, ErrNoSuchGroup
		}

		ref, ok := n2g[name]
		if !ok {
			return nil, ErrNoSuchGroup
		}

		return ref, nil
	})
}

func (this *EtcColonRepository) deleteGroupRef(ctx context.Context, _ *DeleteOpts, selector func() (*etcGroupRef, error)) (rErr error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	f, err := this.openAndLoad(true, true)
	if err != nil {
		return err
	}
	defer common.KeepError(&rErr, f.close)

	ref, err := selector()
	if err != nil {
		return err
	}

	for _, uEntry := range this.handles.passwd.entries {
		if uEntry.entry == nil {
			continue
		}
		if uEntry.entry.gid == ref.etcGroupEntry.gid {
			return fmt.Errorf("cannot delete group because it is still used by user %d(%s)", uEntry.entry.uid, string(uEntry.entry.name))
		}
	}

	delete(this.nameToGroup, string(ref.etcGroupEntry.name))
	delete(this.idToGroup, GroupId(ref.etcGroupEntry.gid))
	this.handles.group.entries = slices.DeleteFunc(this.handles.group.entries, func(candidate etcColonEntry[etcGroupEntry, *etcGroupEntry]) bool {
		if candidate.entry == nil {
			return false
		}
		return candidate.entry.gid == ref.etcGroupEntry.gid
	})

	this.loggerForGroupRef(ref).Info("group deleted")

	return f.save()
}

func (this *EtcColonRepository) preEnsureGroup(ctx context.Context, req *GroupRequirement, opts *EnsureOpts, mutex sync.Locker) (*etcGroupRef, *Group, EnsureResult, error) {
	existing := this.lookupGroupByRequirement(ctx, req, mutex)
	if existing != nil && req.doesFulfilRef(existing) {
		return existing, this.refToGroup(existing), EnsureResultUnchanged, nil
	}

	if existing == nil && !opts.IsCreateAllowed() {
		return nil, nil, EnsureResultError, ErrNoSuchGroup
	}

	if !opts.IsModifyAllowed() {
		return existing, nil, EnsureResultError, ErrGroupDoesNotFulfilRequirement
	}
	return existing, nil, EnsureResultUnknown, nil
}

// EnsureGroup implements Ensurer.EnsureGroup.
func (this *EtcColonRepository) EnsureGroup(ctx context.Context, req *GroupRequirement, opts *EnsureOpts) (_ *Group, _ EnsureResult, rErr error) {
	if req == nil {
		panic("nil group requirement")
	}
	tReq := req.OrDefaults()

	_, group, pResult, err := this.preEnsureGroup(ctx, &tReq, opts, this.mutex.RLocker())
	if err != nil || pResult != EnsureResultUnknown {
		return group, pResult, err
	}

	this.mutex.Lock()
	defer this.mutex.Unlock()
	f, err := this.openAndLoad(true, true)
	if err != nil {
		return nil, EnsureResultError, err
	}
	defer common.KeepError(&rErr, f.close)

	_, group, result, err := this.ensureGroup(ctx, nil, &tReq, opts)
	if err != nil {
		return nil, EnsureResultError, err
	}
	if result == EnsureResultModified || result == EnsureResultCreated {
		if err := f.save(); err != nil {
			return nil, EnsureResultError, err
		}
	}

	return group, result, nil
}

func (this *EtcColonRepository) ensureGroup(ctx context.Context, forUser *Requirement, req *GroupRequirement, opts *EnsureOpts) (*etcGroupRef, *Group, EnsureResult, error) {
	tReq := req.OrDefaultsForUser(forUser)

	existing, group, pResult, err := this.preEnsureGroup(ctx, &tReq, opts, nil)
	if err != nil || pResult != EnsureResultUnknown {
		return existing, group, pResult, err
	}

	if existing == nil {
		ref := tReq.toEtcGroupRef(func() GroupId {
			result := this.findHighestGid(ctx)
			if result < 1000 {
				return 1000
			}
			result++
			if result == 65534 {
				// Yeah... we never want to return 65534, because it is nobody.
				// See: https://wiki.ubuntu.com/nobody
				result++
			}
			return result
		})
		this.handles.group.entries = append(this.handles.group.entries, etcColonEntry[etcGroupEntry, *etcGroupEntry]{
			entry:   ref.etcGroupEntry,
			rawLine: nil,
		})
		this.nameToGroup[string(ref.etcGroupEntry.name)] = ref
		this.idToGroup[GroupId(ref.etcGroupEntry.gid)] = ref

		this.loggerForGroupRef(ref).Info("group created")

		return ref, this.refToGroup(ref), EnsureResultCreated, nil
	}

	oldName := existing.etcGroupEntry.name
	oldGid := existing.etcGroupEntry.gid
	if err := tReq.updateEtcGroupRef(existing); err != nil {
		return existing, nil, EnsureResultError, err
	}

	if !bytes.Equal(oldName, existing.etcGroupEntry.name) {
		delete(this.nameToGroup, string(oldName))
		this.nameToGroup[string(existing.etcGroupEntry.name)] = existing
	}
	if oldGid != existing.etcGroupEntry.gid {
		delete(this.idToGroup, GroupId(existing.etcGroupEntry.gid))
		this.idToGroup[GroupId(existing.etcGroupEntry.gid)] = existing
	}

	this.loggerForGroupRef(existing).Info("group updated")

	return existing, this.refToGroup(existing), EnsureResultModified, nil
}

func (this *EtcColonRepository) ensureGroups(ctx context.Context, reqs *GroupRequirements, opts *EnsureOpts) ([]*etcGroupRef, Groups, error) {
	refs := make([]*etcGroupRef, len(*reqs))
	groups := make(Groups, len(*reqs))
	for i, req := range *reqs {
		ref, v, _, err := this.ensureGroup(ctx, nil, &req, opts)
		if err != nil {
			return nil, nil, err
		}
		refs[i] = ref
		groups[i] = *v
	}

	return refs, groups, nil
}

func (this *EtcColonRepository) findHighestGid(_ context.Context) GroupId {
	var result GroupId
	for _, v := range this.handles.group.entries {
		if v.entry == nil {
			continue
		}
		if v.entry.gid == uint32(65534) && string(v.entry.name) == "nogroup" {
			// Yeah... strange exception, we'll simply skip it. See: https://wiki.ubuntu.com/nobody
			continue
		}
		actual := GroupId(v.entry.gid)
		if actual > result {
			result = actual
		}
	}

	return result
}

func (this *EtcColonRepository) findHighestUid(_ context.Context) Id {
	var result Id
	for _, v := range this.handles.passwd.entries {
		if v.entry == nil {
			continue
		}
		if v.entry.uid == uint32(65534) && string(v.entry.name) == "nobody" {
			// Yeah... strange exception, we'll simply skip it. See: https://wiki.ubuntu.com/nobody
			continue
		}
		actual := Id(v.entry.uid)
		if actual > result {
			result = actual
		}
	}

	return result
}

func (this *EtcColonRepository) refToUser(ctx context.Context, ref *etcPasswdRef) (*User, error) {
	group := this.lookupGroupById(ctx, GroupId(ref.etcPasswdEntry.gid), nil)
	if group == nil {
		group = &Group{GroupId(ref.etcPasswdEntry.gid), fmt.Sprintf("g%d", ref.etcPasswdEntry.gid)}
	}

	var groups Groups
	if u2gs := this.usernameToGroups; u2gs != nil {
		if gs, ok := u2gs[string(ref.etcPasswdEntry.name)]; ok {
			groups = make([]Group, len(gs))
			for i, g := range gs {
				groups[i] = *this.refToGroup(g)
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

func (this *EtcColonRepository) refToGroup(ref *etcGroupRef) *Group {
	return &Group{
		GroupId(ref.gid),
		strings.Clone(string(ref.name)),
	}
}

// Close disposes this repository after usage.
func (this *EtcColonRepository) Close() error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	return this.handles.close()
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
			msgPrefix = "unexpected error"
		}
	}

	if canAddErrIfPresent && err != nil {
		logger = logger.WithError(err)
	}

	logger.Fatal(msgPrefix + "; will exit now to and hope for a restart of this service to reset the state (exit code 17)")
	etcColonRepositoryExitFunc()
}

func (this *EtcColonRepository) scheduleReload(l log.Logger) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	l.Trace("schedule reload of repository")

	this.reloadTimer.Stop()
	if v := this.FileSystemSyncThreshold; v != 0 {
		this.reloadTimer.Reset(v)
	} else {
		this.reloadTimer.Reset(DefaultFileSystemSyncThreshold)
	}
}

func (this *EtcColonRepository) onReloadTimer() {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if err := this.load(context.Background()); err != nil {
		this.onUnhandledAsyncError(this.logger(), err, "cannot reload repository")
	}
}

func (this *EtcColonRepository) load(_ context.Context) (rErr error) {
	l := this.logger()

	start := time.Now()
	if l.IsDebugEnabled() {
		l.Debug("loading...")
	}

	_, err := this.openAndLoad(false, false)
	if err != nil {
		return err
	}

	lw := l.With("duration", fields.LazyFunc(func() any { return time.Since(start).Truncate(time.Microsecond).String() }))
	if l.IsDebugEnabled() {
		lw.Info("loading... DONE!")
	} else {
		lw.Info("loaded")
	}

	return nil
}

func (this *EtcColonRepository) openAndLoad(rw, returnHandles bool) (_ *openedEtcColonRepositoryHandles, rErr error) {
	doNotCloseHandles := false

	f, err := this.handles.open(rw)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !doNotCloseHandles {
			common.KeepError(&rErr, f.close)
		}
	}()

	if err := f.load(); err != nil {
		return nil, err
	}
	this.rebuildIndexes()

	if returnHandles {
		doNotCloseHandles = true
		return f, nil
	}

	return nil, nil
}

func (this *EtcColonRepository) rebuildIndexes() {
	this.nameToGroup, this.idToGroup, this.usernameToGroups = this.loadGroupsRefs()
	usernameToShadow := this.loadShadowsRefs()
	this.nameToUser, this.idToUser = this.loadUsersRefs(usernameToShadow)
}

func (this *EtcColonRepository) loadGroupsRefs() (nameToEtcGroupRef, idToEtcGroupRef, nameToEtcGroupRefs) {
	nameToGroup := make(nameToEtcGroupRef, len(this.handles.group.entries))
	idToGroup := make(idToEtcGroupRef, len(this.handles.group.entries))
	usernameToGroup := nameToEtcGroupRefs{}

	for _, e := range this.handles.group.entries {
		if e.entry == nil {
			continue
		}
		ref := etcGroupRef{e.entry}
		nameToGroup[string(e.entry.name)] = &ref
		idToGroup[GroupId(e.entry.gid)] = &ref
		for _, un := range ref.userNames {
			usernameToGroup[string(un)] = append(usernameToGroup[string(un)], &ref)
		}
	}

	return nameToGroup, idToGroup, usernameToGroup
}

func (this *EtcColonRepository) loadShadowsRefs() map[string]*etcShadowEntry {
	nameToShadow := make(map[string]*etcShadowEntry, len(this.handles.shadow.entries))

	for _, e := range this.handles.shadow.entries {
		if e.entry == nil {
			continue
		}
		nameToShadow[string(e.entry.name)] = e.entry
	}

	return nameToShadow
}

func (this *EtcColonRepository) loadUsersRefs(usernameToShadow map[string]*etcShadowEntry) (nameToEtcPasswdRef, idToEtcPasswdRef) {
	nameToUser := make(nameToEtcPasswdRef, len(this.handles.passwd.entries))
	idToUser := make(idToEtcPasswdRef, len(this.handles.passwd.entries))

	for _, e := range this.handles.passwd.entries {
		if e.entry == nil {
			continue
		}
		shadow := usernameToShadow[string(e.entry.name)]

		ref := etcPasswdRef{e.entry, shadow}

		nameToUser[string(e.entry.name)] = &ref
		idToUser[Id(e.entry.uid)] = &ref
	}

	return nameToUser, idToUser
}

func (this *EtcColonRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("user-repository")
}

func (this *EtcColonRepository) loggerForRef(ref *etcPasswdRef) log.Logger {
	return this.logger().With("user", ref)
}

func (this *EtcColonRepository) loggerForGroupRef(ref *etcGroupRef) log.Logger {
	return this.logger().With("group", ref)
}

func (this *EtcColonRepository) getCreateFilesIfAbsent() bool {
	if v := this.CreateFilesIfAbsent; v != nil {
		return *v
	}
	//goland:noinspection GoBoolExpressions
	return DefaultCreateFilesIfAbsent
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

func (this *EtcColonRepository) watchForChanges(watcher *fsnotify.Watcher) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			l := this.logger().
				With("op", event.Op).
				With("file", event.Name)

			match, err := this.handles.matchesFilename(event.Name)
			if err != nil {
				this.onUnhandledAsyncError(l, err, "cannot evaluate filename of event")
			}
			if !match {
				continue
			}
			switch event.Op {
			case fsnotify.Create, fsnotify.Write, fsnotify.Rename, fsnotify.Remove:
				this.scheduleReload(l)
			default:
				// ignored
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			this.onUnhandledAsyncError(this.logger(), err, "error while handling file watcher events")
		}
	}
}

func (this *EtcColonRepository) killAllOf(ctx context.Context, uid uint32) error {
	fail := func(err error) error {
		return errors.Newf(errors.System, "cannot kill all processes of user %d: %w", uid, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	ps, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return fail(err)
	}

	for _, p := range ps {

		pUids, err := p.UidsWithContext(ctx)
		if err != nil {
			return failf("cannot inspect process %d: %w", p.Pid, err)
		}

		if len(pUids) == 0 {
			continue
		}
		if pUids[0] != int32(uid) {
			continue
		}

		if err := p.KillWithContext(ctx); err != nil {
			return failf("cannot kill process %d: %w", p.Pid, err)
		}
	}

	return nil
}

var etcColonRepositoryExitFunc = func() {
	os.Exit(17)
}

var etcColonRepositoryChownFunc = os.Chown
