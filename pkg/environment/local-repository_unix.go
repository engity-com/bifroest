//go:build unix

package environment

import (
	"context"
	"encoding/json"
	"fmt"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

var (
	_ = RegisterRepository(NewLocalRepository)
)

type LocalRepository struct {
	flow        configuration.FlowName
	conf        *configuration.EnvironmentLocal
	coordinator *localAccountCoordinator

	Logger log.Logger

	userRepository user.CloseableRepository

	targetAccountShellValidator func(string) error
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

	userRepository, err := user.DefaultRepositoryProvider.Create(ctx)
	if err != nil {
		return nil, err
	}

	result := LocalRepository{
		flow:           flow,
		conf:           conf,
		coordinator:    repositoryDependenciesFrom(ctx).localAccounts,
		userRepository: userRepository,
	}

	return &result, nil
}

func (this *LocalRepository) DoesSupportPty(Context, essh.Pty) (bool, error) {
	return true, nil
}

func (this *LocalRepository) Ensure(req Request) (Environment, error) {
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

	if existing, err := this.FindBySession(req.Context(), sess, nil); err != nil {
		if !errors.Is(err, ErrNoSuchEnvironment) {
			return fail(err)
		}
	} else {
		current, ok := existing.(*local)
		if !ok {
			return fail(ErrNotAcceptable)
		}
		target, ok, err := this.validateCurrentTargetAccount(req, current.user)
		if err != nil {
			return fail(err)
		}
		if !ok {
			return fail(ErrNotAcceptable)
		}
		if !this.isCurrentTargetAccount(target, current.user) {
			return fail(ErrNotAcceptable)
		}
		return existing, nil
	}

	accountReq, err := this.conf.User.Render(nil, req)
	if err != nil {
		return fail(err)
	}
	var candidate *user.User
	if accountReq.Name != "" {
		candidate, err = this.userRepository.LookupByName(req.Context(), accountReq.Name)
	} else if accountReq.Uid != nil {
		candidate, err = this.userRepository.LookupById(req.Context(), *accountReq.Uid)
	}
	if errors.Is(err, user.ErrNoSuchUser) {
		candidate, err = nil, nil
	}
	if err != nil {
		return fail(err)
	}
	managed, err := this.isManagedUser(req.Context(), candidate)
	if err != nil {
		return fail(err)
	}
	manageSystemUsers, err := this.conf.ManageSystemUsers.Render(req)
	if err != nil {
		return fail(err)
	}
	ensureOpts, err := this.getEnsureOptsOf(req, candidate, managed)
	if err != nil {
		return fail(err)
	}
	if candidate != nil && candidate.Uid == 0 && !manageSystemUsers {
		ensureOpts.updateIfDifferent = false
	}
	if accountReq.Uid != nil && *accountReq.Uid == 0 && !manageSystemUsers &&
		((candidate == nil && ensureOpts.createIfAbsent) || (candidate != nil && ensureOpts.updateIfDifferent)) {
		return failf(errors.Config, "refusing to create or modify account with protected UID 0")
	}
	if candidate != nil && ensureOpts.updateIfDifferent && accountReq.Name == "" && accountReq.Uid != nil {
		return failf(errors.Config, "cannot update existing local account by UID alone; configure its name explicitly")
	}

	var u *user.User
	if !ensureOpts.canCreateOrUpdate() {
		if u, err = this.lookupUserBy(req); err != nil {
			return fail(err)
		}
	} else {
		if u, _, err = this.ensureUserByTask(req, accountReq, candidate, &ensureOpts, manageSystemUsers); err != nil {
			return fail(err)
		}
	}
	target, ok, err := this.validateCurrentTargetAccount(req, u)
	if err != nil {
		return fail(err)
	}
	if !ok {
		return fail(ErrNotAcceptable)
	}
	actual, accepted, err := this.acceptedTargetAccount(target, u)
	if err != nil {
		return fail(err)
	}
	if !accepted {
		return fail(ErrNotAcceptable)
	}
	if actual != nil {
		u = actual
	}
	managed, err = this.isManagedUser(req.Context(), u)
	if err != nil {
		return fail(err)
	}
	policyReq := this.withValidatedTargetAccountRequest(req, u)
	lt, err := this.newLocalToken(u, policyReq, managed, manageSystemUsers)
	if err != nil {
		return fail(err)
	}
	if ltb, err := json.Marshal(lt); err != nil {
		return failf(errors.System, "cannot marshal environment token: %w", err)
	} else if err := sess.SetEnvironmentToken(req.Context(), ltb); err != nil {
		return failf(errors.System, "cannot store environment token at session: %w", err)
	}

	return this.new(u, sess, lt.PortForwardingAllowed, lt), nil
}

func (this *LocalRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}
	var lt localToken
	userNotFound := func(userRef any) (Environment, error) {
		if !opts.IsAutoCleanUpAllowed() {
			return failf(errors.Expired, "user %q of session cannot longer be found; treat as expired", userRef)
		}
		_, canCleanAbsentHome := this.userRepository.(interface {
			DeleteHomeByAbsentIdentity(context.Context, user.Id, string, string) error
		})
		if lt.Version == 2 && lt.User.Name != "" && lt.User.Uid != nil &&
			((lt.User.KillProcessesOnDispose && !lt.User.ProcessesKilledOnDispose) ||
				(lt.User.DeleteOnDispose && lt.User.DeleteHomeTogetherWithUser && canCleanAbsentHome)) {
			pending := this.new(&user.User{Name: lt.User.Name, Uid: *lt.User.Uid}, sess, lt.PortForwardingAllowed, &lt)
			pending.accountMissing = true
			return pending, nil
		}
		// Clear the stored token.
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return failf(errors.System, "cannot clear existing environment token of session after its user (%v) does not seem to exist any longer: %w", userRef, err)
		}
		opts.GetLogger(this.logger).
			With("session", sess).
			With("user", userRef).
			Debug("session's user does not longer seem to exist; treat environment as expired; therefore according environment token was removed from session")
		return nil, ErrNoSuchEnvironment
	}

	ltb, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot get environment token: %w", err)
	}
	if len(ltb) == 0 {
		return fail(ErrNoSuchEnvironment)
	}
	if err := json.Unmarshal(ltb, &lt); err != nil {
		return failf(errors.System, "cannot decode environment token: %w", err)
	}
	if lt.Version != 2 {
		lt.User.DeleteOnDispose = false
		lt.User.DeleteHomeTogetherWithUser = false
		lt.User.KillProcessesOnDispose = false
	}

	var u *user.User
	if v := lt.User.Name; len(v) != 0 {
		if u, err = this.userRepository.LookupByName(ctx, v); errors.Is(err, user.ErrNoSuchUser) {
			return userNotFound(v)
		} else if err != nil {
			return failf(errors.System, "cannot lookup environment's user by name %q: %w", v, err)
		}
	} else if v := lt.User.Uid; v != nil {
		if u, err = this.userRepository.LookupById(ctx, *v); errors.Is(err, user.ErrNoSuchUser) {
			return userNotFound(v)
		} else if err != nil {
			return failf(errors.System, "cannot lookup environment's user by id %v: %w", *v, err)
		}
	} else {
		return failf(errors.System, "environment token does not contain valid user information: %w", err)
	}
	if lt.User.Uid != nil && u.Uid != *lt.User.Uid {
		return userNotFound(lt.User.Name)
	}
	if ok, err := this.isStoredTargetAccountAccepted(ctx, u, &lt); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}
	if ok, err := this.isTargetAccountAccepted(u); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	return this.new(u, sess, lt.PortForwardingAllowed, &lt), nil
}

type localEnsureOpts struct {
	createIfAbsent    bool
	updateIfDifferent bool
}

func (this localEnsureOpts) canCreateOrUpdate() bool {
	return this.createIfAbsent || this.updateIfDifferent
}

func (this *LocalRepository) getEnsureOptsOf(r Request, candidate *user.User, managed bool) (result localEnsureOpts, err error) {
	fail := func(err error) (localEnsureOpts, error) {
		return localEnsureOpts{}, err
	}
	failf := func(msg string, args ...any) (localEnsureOpts, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if result.createIfAbsent, err = this.conf.CreateIfAbsent.Render(r); err != nil {
		return failf("cannot render createIfAbsent: %w", err)
	}

	if candidate != nil {
		if result.updateIfDifferent, err = this.conf.UpdateIfDifferent.Render(localTemplateContext{Request: r, user: candidate, managed: managed}); err != nil {
			return failf("cannot render updateIfDifferent: %w", err)
		}
	}

	return result, nil
}

func (this *LocalRepository) lookupUserBy(ctx Context) (u *user.User, err error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	if v := this.conf.User.Name; !v.IsZero() {
		if u, err = this.lookupByName(ctx, v); err != nil {
			return fail(err)
		}
	} else if v := this.conf.User.Uid; v != nil {
		if u, err = this.lookupByUid(ctx, *v); err != nil {
			return fail(err)
		}
	} else {
		return failf("the system isn't allowed to update nor create users and there is neither a user name nor user id configured")
	}

	return u, nil
}

func (this *LocalRepository) ensureUserByTask(r Request, req *user.Requirement, candidate *user.User, opts *localEnsureOpts, allowSystemUsers bool) (*user.User, user.EnsureResult, error) {
	if (candidate == nil && opts.createIfAbsent) || (candidate != nil && opts.updateIfDifferent) {
		if !allowSystemUsers {
			group, err := this.userRepository.LookupGroupByName(r.Context(), this.conf.ManagedGroup)
			if err == nil && group.Gid == 0 {
				return nil, user.EnsureResultError, fmt.Errorf("refusing to manage privileged group %q", this.conf.ManagedGroup)
			}
			if err != nil && !errors.Is(err, user.ErrNoSuchGroup) {
				return nil, user.EnsureResultError, err
			}
		}
		if _, validated := this.userRepository.(validatedUserEnsureRepository); !validated {
			createGroup := true
			modifyGroup := false
			if _, _, err := this.userRepository.EnsureGroup(r.Context(), &user.GroupRequirement{Name: this.conf.ManagedGroup}, &user.EnsureOpts{
				CreateAllowed: &createGroup,
				ModifyAllowed: &modifyGroup,
			}); err != nil {
				return nil, user.EnsureResultError, fmt.Errorf("cannot ensure managed group: %w", err)
			}
		}
		// Keep the ordinary group requirements intact, including their defaults.
		groups := req.OrDefaults().Groups
		for _, group := range groups {
			if group.Name == this.conf.ManagedGroup {
				req.Groups = groups
				return this.ensureUser(r, req, opts)
			}
		}
		req.Groups = append(groups, user.GroupRequirement{Name: this.conf.ManagedGroup})
	}

	return this.ensureUser(r, req, opts)
}

func (this *LocalRepository) isManagedUser(ctx context.Context, u *user.User) (bool, error) {
	if u == nil {
		return false, nil
	}
	group, err := this.userRepository.LookupGroupByName(ctx, this.conf.ManagedGroup)
	if errors.Is(err, user.ErrNoSuchGroup) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if u.Group.Gid == group.Gid {
		return true, nil
	}
	for _, candidate := range u.Groups {
		if candidate.Gid == group.Gid {
			return true, nil
		}
	}
	return false, nil
}

func (this *LocalRepository) lookupByUid(ctx Context, tmpl template.TextMarshaller[user.Id, *user.Id]) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	uid, err := tmpl.Render(ctx)
	if err != nil {
		return failf("cannot render UID: %w", err)
	}

	return this.userRepository.LookupById(ctx.Context(), uid)
}

func (this *LocalRepository) lookupByName(ctx Context, tmpl template.String) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	name, err := tmpl.Render(ctx)
	if err != nil {
		return failf("cannot render user name: %w", err)
	}

	return this.userRepository.LookupByName(ctx.Context(), name)
}

type validatedUserEnsureRepository interface {
	EnsureValidated(context.Context, *user.Requirement, *user.EnsureOpts, func(*user.User) error) (*user.User, user.EnsureResult, error)
}

func (this *LocalRepository) ensureUser(request Request, req *user.Requirement, opts *localEnsureOpts) (u *user.User, result user.EnsureResult, err error) {
	ensureOpts := &user.EnsureOpts{
		CreateAllowed: &opts.createIfAbsent,
		ModifyAllowed: &opts.updateIfDifferent,
	}
	if repository, ok := this.userRepository.(validatedUserEnsureRepository); ok {
		u, result, err = repository.EnsureValidated(request.Context(), req, ensureOpts, func(target *user.User) error {
			return this.validateProvisionedTargetAccount(request, target)
		})
	} else {
		u, result, err = this.userRepository.Ensure(request.Context(), req, ensureOpts)
	}
	if err != nil {
		return nil, user.EnsureResultError, fmt.Errorf("cannot ensure user: %w", err)
	}
	return u, result, nil
}

func (this *LocalRepository) Close() error {
	return this.userRepository.Close()
}

func (this *LocalRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
