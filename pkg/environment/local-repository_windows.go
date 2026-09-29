//go:build windows

package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

type LocalRepository struct {
	flow        configuration.FlowName
	conf        *configuration.EnvironmentLocal
	coordinator *localAccountCoordinator

	Logger log.Logger
}

func NewLocalRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentLocal, _ alternatives.Provider, _ imp.Imp) (*LocalRepository, error) {
	fail := func(err error) (*LocalRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*LocalRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := LocalRepository{
		flow:        flow,
		conf:        conf,
		coordinator: repositoryDependenciesFrom(ctx).localAccounts,
	}

	return &result, nil
}

func (this *LocalRepository) DoesSupportPty(_ Context, pty essh.Pty) (bool, error) {
	w := pty.Window
	return w.Width > 0 && w.Width <= 32767 && w.Height > 0 && w.Height <= 32767 &&
		windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find() == nil, nil
}

func (this *LocalRepository) lookupConfiguredAccount(ctx Context) (account windowsLocalAccount, name, uid string, err error) {
	if name, err = this.conf.Name.Render(ctx); err != nil {
		return account, "", "", fmt.Errorf("cannot evaluate local account name: %w", err)
	}
	if uid, err = this.conf.Uid.Render(ctx); err != nil {
		return account, "", "", fmt.Errorf("cannot evaluate local account UID: %w", err)
	}
	if name == "" && uid == "" {
		return account, "", "", fmt.Errorf("local account name or UID is required")
	}
	if name != "" && !validLocalSAMName(name) {
		return account, "", "", fmt.Errorf("invalid local SAM account name %q", name)
	}
	if uid != "" {
		sid, parseErr := windows.StringToSid(uid)
		if parseErr != nil || sid == nil || !sid.IsValid() {
			return account, "", "", fmt.Errorf("invalid local account UID %q: %v", uid, parseErr)
		}
		uid = sid.String()
	}
	if name != "" {
		account, err = lookupLocalWindowsAccount(name)
	} else {
		account, err = lookupLocalWindowsAccountByUID(uid)
	}
	if err == nil && uid != "" && account.SID != uid {
		return windowsLocalAccount{}, "", "", fmt.Errorf("local account %q does not match UID %q", name, uid)
	}
	return account, name, uid, err
}

func (this *LocalRepository) Ensure(req Request) (_ Environment, rErr error) {
	if this.coordinator != nil {
		this.coordinator.mu.Lock()
		defer this.coordinator.mu.Unlock()
	}
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	if ok, err := this.WillBeAccepted(req); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	sess := req.Authorization().FindSession()
	if sess == nil {
		return failf(errors.System, "authorization without session")
	}

	account, name, uid, err := this.lookupConfiguredAccount(req)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return failf(errors.Config, "invalid local account: %w", err)
	}
	if err == nil && !localSAMProtectedAccount(account) {
		disabled, flagErr := localWindowsAccountDisabled(account.Name, account.SID)
		if flagErr != nil {
			return fail(flagErr)
		}
		if disabled {
			return failf(errors.Expired, "local account %q is disabled; check incomplete provisioning", account.Name)
		}
	}
	var createdName, createdSID string
	defer func() {
		if createdSID != "" && rErr != nil {
			if disableErr := disableLocalWindowsAccount(createdName, createdSID, this.conf.ManagedGroup); disableErr != nil {
				rErr = fmt.Errorf("%w; additionally cannot disable incomplete local account %q: %v", rErr, createdName, disableErr)
			}
		}
	}()
	if existing, restoreErr := this.FindBySession(req.Context(), sess, nil); restoreErr == nil {
		if err != nil {
			return fail(err)
		}
		if current := existing.(*local).user; !strings.EqualFold(current.Name, account.Name) || current.SID != account.SID {
			return failf(errors.Expired, "local account identity changed for existing session")
		}
		return existing, nil
	} else if !errors.Is(restoreErr, ErrNoSuchEnvironment) {
		return fail(restoreErr)
	}
	exists := err == nil
	managed := false
	if exists {
		managed, err = IsLocalWindowsAccountInGroup(account.Name, account.SID, this.conf.ManagedGroup, true)
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			managed, err = false, nil
		}
		if err != nil {
			return fail(err)
		}
		account.DisplayName, err = localSAMDisplayName(account.Name)
		if err != nil {
			return fail(err)
		}
		account.Groups, err = lookupWindowsLocalUserGroups(account.Name, account.SID)
		if err != nil {
			return fail(err)
		}
	}
	ctx := localTemplateContext{Request: req, managed: managed}
	if exists {
		ctx.user = account
	}
	allowSystemUsers, err := this.conf.ManageSystemUsers.Render(req)
	if err != nil {
		return fail(err)
	}
	create, err := this.conf.CreateIfAbsent.Render(req)
	if err != nil {
		return fail(err)
	}
	if !exists && uid != "" {
		if create {
			return failf(errors.Config, "cannot create a Windows account with a specified UID (SID) %q", uid)
		}
		return failf(errors.Config, "local Windows account UID %q not found", uid)
	}
	update := false
	if exists {
		update, err = this.conf.UpdateIfDifferent.Render(ctx)
		if err != nil {
			return fail(err)
		}
	}
	var groups []windowsLocalGroupRequirement
	var skel string
	if (!exists && create) || (exists && update && (!localSAMProtectedAccount(account) || allowSystemUsers)) {
		required, renderErr := this.conf.Groups.Render(req)
		if renderErr != nil {
			return fail(renderErr)
		}
		groups = make([]windowsLocalGroupRequirement, len(required))
		for i, group := range required {
			groups[i] = windowsLocalGroupRequirement{Name: group.Name, SID: group.Gid}
			if _, err := validateWindowsLocalGroupRequirement(groups[i]); err != nil {
				return failf(errors.Config, "invalid local group requirement %d: %w", i, err)
			}
		}
	}
	if !exists && create && !this.conf.Skel.IsZero() {
		skel, err = this.conf.Skel.Render(req)
		if err != nil {
			return fail(err)
		}
		if skel == "" {
			return failf(errors.Config, "skel cannot render to an empty path")
		}
		if fi, err := os.Lstat(skel); err != nil || !fi.IsDir() {
			return failf(errors.Config, "skel %q is not a readable directory: %v", skel, err)
		}
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			return fail(err)
		}
		self, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || self == nil || self.User.Sid == nil || !self.User.Sid.Equals(system) {
			return failf(errors.Config, "skel requires Bifröst to run as LocalSystem: %v", err)
		}
	}
	if !exists {
		if !create {
			return failf(errors.Config, "local Windows account not found: %q", name)
		}
		display := ""
		if !this.conf.DisplayName.IsZero() {
			display, err = this.conf.DisplayName.Render(req)
			if err != nil {
				return fail(err)
			}
		}
		var createErr error
		createdSID, createErr = CreateLocalWindowsAccount(name, display, this.conf.ManagedGroup)
		if createErr != nil {
			return fail(createErr)
		}
		createdName = name
		account, err = lookupLocalWindowsAccount(name)
		if err != nil {
			return fail(err)
		}
		if account.SID != createdSID {
			return failf(errors.Expired, "newly created local account changed SID")
		}
	} else if update && (!localSAMProtectedAccount(account) || allowSystemUsers) {
		if err = EnsureLocalWindowsAccountGroup(account.Name, account.SID, this.conf.ManagedGroup, allowSystemUsers); err != nil {
			return fail(err)
		}
		if !this.conf.DisplayName.IsZero() {
			display, renderErr := this.conf.DisplayName.Render(req)
			if renderErr != nil {
				return fail(renderErr)
			}
			if err = UpdateLocalWindowsAccountDisplayName(account.Name, account.SID, display, true, allowSystemUsers); err != nil {
				return fail(err)
			}
		}
	}
	if len(groups) > 0 {
		if _, err := ensureWindowsLocalUserGroups(account.Name, account.SID, groups, allowSystemUsers); err != nil {
			return fail(err)
		}
	}
	if skel != "" {
		token, release, logonErr := account.logon()
		if logonErr != nil {
			return fail(logonErr)
		}
		profile, profileErr := token.GetUserProfileDirectory()
		if profileErr == nil {
			profileErr = copyLocalWindowsProfileTemplate(skel, profile, token)
		}
		release()
		if profileErr != nil {
			return failf(errors.System, "cannot populate profile of new account %q: %w", account.Name, profileErr)
		}
	}
	// Only the observed post-ensure membership grants deletion rights.
	managed, err = IsLocalWindowsAccountInGroup(account.Name, account.SID, this.conf.ManagedGroup, true)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		managed, err = false, nil
	}
	if err != nil {
		return fail(err)
	}
	account.DisplayName, err = localSAMDisplayName(account.Name)
	if err != nil {
		return fail(err)
	}
	account.Groups, err = lookupWindowsLocalUserGroups(account.Name, account.SID)
	if err != nil {
		return fail(err)
	}

	lt, err := this.newLocalToken(req, account, managed, allowSystemUsers)
	if err != nil {
		return fail(err)
	}
	if ltb, err := json.Marshal(lt); err != nil {
		return failf(errors.System, "cannot marshal environment token: %w", err)
	} else if err := sess.SetEnvironmentToken(req.Context(), ltb); err != nil {
		return failf(errors.System, "cannot store environment token at session: %w", err)
	}

	return this.new(account, sess, lt.PortForwardingAllowed, lt), nil
}

func (this *LocalRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ltb, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot get environment token: %w", err)
	}
	if len(ltb) == 0 {
		return fail(ErrNoSuchEnvironment)
	}
	var lt localToken
	if err := json.Unmarshal(ltb, &lt); err != nil {
		return failf(errors.System, "cannot decode environment token: %w", err)
	}
	if lt.Version != 2 {
		lt.DeleteOnDispose, lt.DeleteProfileOnDispose = false, false
	}
	if lt.User.Name == "" || lt.User.SID == "" {
		return this.expireLocalToken(ctx, sess, opts)
	}
	account, err := lookupLocalWindowsAccount(lt.User.Name)
	if err != nil || account.SID != lt.User.SID {
		account, err = lookupLocalWindowsAccountByUID(lt.User.SID)
	}
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return failf(errors.System, "cannot resolve session's local account: %w", err)
	}
	if err != nil || account.SID != lt.User.SID {
		if opts.IsAutoCleanUpAllowed() && lt.Version == 2 &&
			((lt.DeleteOnDispose && lt.DeleteProfileOnDispose) ||
				(lt.KillProcessesOnDispose && !lt.ProcessesKilledOnDispose)) {
			pending := this.new(lt.User, sess, lt.PortForwardingAllowed, &lt)
			pending.accountMissing = true
			return pending, nil
		}
		return this.expireLocalToken(ctx, sess, opts)
	}

	return this.new(account, sess, lt.PortForwardingAllowed, &lt), nil
}

func (this *LocalRepository) expireLocalToken(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	if opts.IsAutoCleanUpAllowed() {
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return nil, errors.System.Newf("cannot clear expired local account token: %w", err)
		}
		return nil, ErrNoSuchEnvironment
	}
	return nil, errors.Expired.Newf("local account of session no longer exists or changed SID")
}

func (this *LocalRepository) IsSessionCompatible(ctx context.Context, sess session.Session) (bool, error) {
	token, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return false, err
	}
	if len(token) == 0 {
		return true, nil
	}
	var stored localToken
	if err := json.Unmarshal(token, &stored); err != nil || stored.User.Name == "" || stored.User.SID == "" {
		return false, nil
	}
	account, err := lookupLocalWindowsAccount(stored.User.Name)
	if errors.Is(err, errLocalWindowsAccountNotFound) || (err == nil && account.SID != stored.User.SID) {
		account, err = lookupLocalWindowsAccountByUID(stored.User.SID)
	}
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return false, err
	}
	return err == nil && account.SID == stored.User.SID, nil
}

func (this *LocalRepository) IsSessionCompatibleWith(ctx Context, sess session.Session) (bool, error) {
	compatible, err := this.IsSessionCompatible(ctx.Context(), sess)
	if err != nil || !compatible {
		return compatible, err
	}
	account, _, _, err := this.lookupConfiguredAccount(ctx)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return false, err
	}
	if err != nil {
		return false, nil
	}
	stored, err := sess.EnvironmentToken(ctx.Context())
	if err != nil {
		return false, err
	}
	if len(stored) == 0 {
		return true, nil
	}
	var token localToken
	if err := json.Unmarshal(stored, &token); err != nil {
		return false, nil
	}
	return strings.EqualFold(account.Name, token.User.Name) && account.SID == token.User.SID, nil
}

func (this *LocalRepository) Close() error {
	return nil
}
