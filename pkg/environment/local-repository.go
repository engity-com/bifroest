//go:build linux

package environment

import (
	"context"
	"encoding/json"
	"fmt"
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

var (
	_ = RegisterRepository(NewLocalRepository)
)

type LocalRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentLocal

	Logger log.Logger

	userRepository user.CloseableRepository
}

func NewLocalRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentLocal) (*LocalRepository, error) {
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
		userRepository: userRepository,
	}

	return &result, nil
}

func (this *LocalRepository) WillBeAccepted(req Request) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(req); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *LocalRepository) Ensure(req Request) (Environment, error) {
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
			req.Logger().
				WithError(err).
				Warn("cannot restore environment from existing session; will create a new one")
		}
	} else {
		return existing, nil
	}

	ensureOpts, err := this.getEnsureOptsOf(req)
	if err != nil {
		return fail(err)
	}

	var u *user.User
	var userIsManaged bool
	if !ensureOpts.canCreateOrUpdate() {
		if u, err = this.lookupUserBy(req); err != nil {
			return fail(err)
		}
		userIsManaged = false
	} else {
		if u, _, err = this.ensureUserByTask(req, &ensureOpts); err != nil {
			return fail(err)
		}
		userIsManaged = true
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}

	deleteOnDispose, err := this.conf.Dispose.DeleteManagedUser.Render(req)
	if err != nil {
		return fail(err)
	}
	deleteHomeDirOnDispose, err := this.conf.Dispose.DeleteManagedUserHomeDir.Render(req)
	if err != nil {
		return fail(err)
	}
	killProcessesOnDispose, err := this.conf.Dispose.KillManagedUserProcesses.Render(req)
	if err != nil {
		return fail(err)
	}

	lt := localToken{
		localTokenUser{
			u.Name,
			common.P(u.Uid),
			userIsManaged,
			deleteOnDispose && userIsManaged,
			deleteHomeDirOnDispose && deleteOnDispose && userIsManaged,
			killProcessesOnDispose && userIsManaged,
		},
		portForwardingAllowed,
	}
	if ltb, err := json.Marshal(lt); err != nil {
		return failf(errors.System, "cannot marshal environment token: %w", err)
	} else if err := sess.SetEnvironmentToken(req.Context(), ltb); err != nil {
		return failf(errors.System, "cannot store environment token at session: %w", err)
	}

	return &local{
		this,
		sess,
		u,
		portForwardingAllowed,
		lt.User.DeleteOnDispose,
		lt.User.DeleteHomeDirOnDispose,
		lt.User.KillProcessesOnDispose,
	}, nil
}

func (this *LocalRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}
	userNotFound := func(userRef any) (Environment, error) {
		if !opts.IsAutoCleanUpAllowed() {
			return failf(errors.Expired, "user %q of session cannot longer be found; treat as expired", userRef)
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
	var tb localToken
	if err := json.Unmarshal(ltb, &tb); err != nil {
		return failf(errors.System, "cannot decode environment token: %w", err)
	}

	var u *user.User
	if v := tb.User.Name; len(v) != 0 {
		if u, err = this.userRepository.LookupByName(ctx, v); errors.Is(err, user.ErrNoSuchUser) {
			return userNotFound(v)
		} else if err != nil {
			return failf(errors.System, "cannot lookup environment's user by name %q: %w", v, err)
		}
	} else if v := tb.User.Uid; v != nil {
		if u, err = this.userRepository.LookupById(ctx, *v); errors.Is(err, user.ErrNoSuchUser) {
			return userNotFound(v)
		} else if err != nil {
			return failf(errors.System, "cannot lookup environment's user by id %v: %w", *v, err)
		}
	} else {
		return failf(errors.System, "environment token does not contain valid user information: %w", err)
	}

	return &local{
		this,
		sess,
		u,
		tb.PortForwardingAllowed,
		tb.User.DeleteOnDispose,
		tb.User.DeleteHomeDirOnDispose,
		tb.User.KillProcessesOnDispose,
	}, nil
}

type localEnsureOpts struct {
	createIfAbsent    bool
	updateIfDifferent bool
}

func (this localEnsureOpts) canCreateOrUpdate() bool {
	return this.createIfAbsent || this.updateIfDifferent
}

func (this *LocalRepository) getEnsureOptsOf(r Request) (result localEnsureOpts, err error) {
	fail := func(err error) (localEnsureOpts, error) {
		return localEnsureOpts{}, err
	}
	failf := func(msg string, args ...any) (localEnsureOpts, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if result.createIfAbsent, err = this.conf.CreateIfAbsent.Render(r); err != nil {
		return failf("cannot render createIfAbsent: %w", err)
	}

	if result.updateIfDifferent, err = this.conf.UpdateIfDifferent.Render(r); err != nil {
		return failf("cannot render updateIfDifferent: %w", err)
	}

	return result, nil
}

func (this *LocalRepository) lookupUserBy(req Request) (u *user.User, err error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	if v := this.conf.User.Name; !v.IsZero() {
		if u, err = this.lookupByName(req, v); err != nil {
			return fail(err)
		}
	} else if v := this.conf.User.Uid; v != nil {
		if u, err = this.lookupByUid(req, *v); err != nil {
			return fail(err)
		}
	} else {
		return failf("the system isn't allowed to update nor create users and there is neither a user name nor user id configured")
	}

	return u, nil
}

func (this *LocalRepository) ensureUserByTask(r Request, opts *localEnsureOpts) (*user.User, user.EnsureResult, error) {
	fail := func(err error) (*user.User, user.EnsureResult, error) {
		return nil, 0, err
	}
	failf := func(msg string, args ...any) (*user.User, user.EnsureResult, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	req, err := this.conf.User.Render(nil, r)
	if err != nil {
		return failf("cannot render user requirement: %w", err)
	}

	return this.ensureUser(r.Context(), req, opts)
}

func (this *LocalRepository) lookupByUid(r Request, tmpl template.TextMarshaller[user.Id, *user.Id]) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	uid, err := tmpl.Render(r)
	if err != nil {
		return failf("cannot render UID: %w", err)
	}

	return this.userRepository.LookupById(r.Context(), uid)
}

func (this *LocalRepository) lookupByName(r Request, tmpl template.String) (*user.User, error) {
	fail := func(err error) (*user.User, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*user.User, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	name, err := tmpl.Render(r)
	if err != nil {
		return failf("cannot render user name: %w", err)
	}

	return this.userRepository.LookupByName(r.Context(), name)
}

func (this *LocalRepository) ensureUser(ctx context.Context, req *user.Requirement, opts *localEnsureOpts) (u *user.User, er user.EnsureResult, err error) {
	u, er, err = this.userRepository.Ensure(ctx, req, &user.EnsureOpts{
		CreateAllowed: &opts.createIfAbsent,
		ModifyAllowed: &opts.updateIfDifferent,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("cannot ensure user: %w", err)
	}
	return u, er, nil
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
