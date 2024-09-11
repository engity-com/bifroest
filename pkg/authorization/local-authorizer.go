//go:build unix

package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	log "github.com/echocat/slf4g"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
)

var (
	_ = RegisterAuthorizer(NewLocal)
)

type LocalAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationLocal

	Logger log.Logger

	userRepository user.CloseableRepository
}

func NewLocal(ctx context.Context, flow configuration.FlowName, conf *configuration.AuthorizationLocal) (*LocalAuthorizer, error) {
	fail := func(err error) (*LocalAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*LocalAuthorizer, error) {
		return fail(errors.Newf(errors.Config, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	userRepository, err := user.DefaultRepositoryProvider.Create(ctx)
	if err != nil {
		return nil, err
	}

	result := LocalAuthorizer{
		flow:           flow,
		conf:           conf,
		userRepository: userRepository,
	}

	return &result, nil
}

func (this *LocalAuthorizer) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize local %q via authorized keys: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if len(this.conf.AuthorizedKeys) == 0 {
		req.Logger().Debug("authorized keys disabled for local user")
		return Forbidden(req.Remote()), nil
	}

	u, err := this.userRepository.LookupByName(req.Context(), req.Remote().User())
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Debug("local user not found")
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user: %w", err)
	}

	candidate := local{
		u,
		req.Remote(),
		nil,
		this.flow,
		nil,
		nil,
	}

	if ok, err := req.Validate(&candidate); err != nil {
		return failf("cannot validate request: %w", err)
	} else if !ok {
		return Forbidden(req.Remote()), nil
	}

	sess, err := req.Sessions().FindByPublicKey(req.Context(), req.RemotePublicKey(), (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		if ok, err := this.isAuthorizedViaPublicKey(req, u); err != nil {
			return fail(err)
		} else if !ok {
			return Forbidden(req.Remote()), nil
		}
		sess, err = this.ensureSessionFor(req, u)
		if err != nil {
			return fail(err)
		}

		candidate.session = sess
	} else if err != nil {
		return failf("cannot find session: %w", err)
	} else {
		candidate.session = sess
		candidate.sessionsPublicKey = req.RemotePublicKey()
	}

	return &candidate, nil
}

func (this *LocalAuthorizer) isAuthorizedViaPublicKey(req PublicKeyRequest, u *user.User) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(msg string, args ...any) (bool, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	files, err := this.getAuthorizedKeysFilesOf(req, u)
	if err != nil {
		return failf("cannot get authorized keys files of user: %w", err)
	}
	if len(files) == 0 {
		req.Logger().Debug("local user does not has any authorized keys file")
		return false, nil
	}

	foundMatch, err := crypto.DoWithEachAuthorizedKey[bool](false, func(candidate ssh.PublicKey) (ok bool, canContinue bool, err error) {
		remote := req.RemotePublicKey()

		if remote.Type() != candidate.Type() {
			return false, true, nil
		}
		if !bytes.Equal(remote.Marshal(), candidate.Marshal()) {
			return false, true, nil
		}

		return true, false, nil
	}, files...)
	if err != nil {
		return fail(err)
	}

	if !foundMatch {
		req.Logger().Debug("presented public key does not match any authorized keys of local user")
		return false, nil
	}

	return true, nil
}

type userEnabledRequest struct {
	Request
	user *user.User
}

func (this *userEnabledRequest) GetField(name string) (any, bool) {
	switch name {
	case "user":
		return this.user, true
	default:
		return nil, false
	}
}

func (this *LocalAuthorizer) getAuthorizedKeysFilesOf(req PublicKeyRequest, u *user.User) ([]string, error) {
	ctx := userEnabledRequest{req, u}
	return common.MapSliceErr(this.conf.AuthorizedKeys, func(tmpl template.String) (string, error) {
		return tmpl.Render(&ctx)
	})
}

func (this *LocalAuthorizer) ensureSessionFor(req Request, u *user.User) (session.Session, error) {
	fail := func(err error) (session.Session, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (session.Session, error) {
		return fail(errors.Newf(errors.System, msg, args...))
	}

	buf := localToken{
		User: localTokenUser{
			Name: u.Name,
			Uid:  common.P(u.Uid),
		},
		EnvVars: nil,
	}
	at, err := json.Marshal(buf)
	if err != nil {
		return failf("cannot marshal authorization token: %w", err)
	}

	sess, err := req.Sessions().FindByAccessToken(req.Context(), at, (&session.FindOpts{}).WithPredicate(
		session.IsFlow(this.flow),
		session.IsStillValid,
		session.IsRemoteName(req.Remote().User()),
	))
	if errors.Is(err, session.ErrNoSuchSession) {
		sess, err = req.Sessions().Create(req.Context(), this.flow, req.Remote(), at)
	}
	if err != nil {
		return fail(err)
	}

	return sess, nil
}

func (this *LocalAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize local %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	allowed, err := this.conf.Password.Allowed.Render(req)
	if err != nil {
		return failf("cannot evaluate of user is allowed: %w", err)
	}
	if !allowed {
		req.Logger().Debug("passwords are disabled for local user")
		return Forbidden(req.Remote()), nil
	}

	username, ev, ok, err := this.checkPassword(req, req.Remote().User(), this.validatePassword)
	if err != nil {
		return failf("cannot validate password: %w", err)
	}
	if !ok {
		return Forbidden(req.Remote()), nil
	}

	u, err := this.userRepository.LookupByName(req.Context(), username)
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Warn("local user %q not found; but it was just resolve before", username)
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user %q: %w", username, err)
	}

	candidate := local{
		u,
		req.Remote(),
		ev,
		this.flow,
		nil,
		nil,
	}

	if ok, err := req.Validate(&candidate); err != nil {
		return failf("cannot validate request: %w", err)
	} else if !ok {
		return Forbidden(req.Remote()), nil
	}

	sess, err := this.ensureSessionFor(req, u)
	if err != nil {
		return failf("cannot create session: %w", err)
	}

	candidate.session = sess

	return &candidate, nil
}

func (this *LocalAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize local %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	allowed, err := this.conf.Password.InteractiveAllowed.Render(req)
	if err != nil {
		return failf("cannot evaluate of user is allowed: %w", err)
	}
	if !allowed {
		req.Logger().Debug("passwords are disabled for local user")
		return Forbidden(req.Remote()), nil
	}

	username, ev, ok, err := this.checkInteractive(req, req.Remote().User(), this.validatePassword)
	if err != nil {
		return failf("cannot validate password: %w", err)
	}
	if !ok {
		return Forbidden(req.Remote()), nil
	}

	u, err := this.userRepository.LookupByName(req.Context(), username)
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Warn("local user %q not found; but it was just resolve before", username)
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user %q: %w", username, err)
	}

	candidate := local{
		u,
		req.Remote(),
		ev,
		this.flow,
		nil,
		nil,
	}

	if ok, err := req.Validate(&candidate); err != nil {
		return failf("cannot validate request: %w", err)
	} else if !ok {
		return Forbidden(req.Remote()), nil
	}

	sess, err := this.ensureSessionFor(req, u)
	if err != nil {
		return failf("cannot create session: %w", err)
	}

	candidate.session = sess

	return &candidate, nil
}

func (this *LocalAuthorizer) validatePassword(password string, req Request) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(message string, args ...any) (bool, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if len(password) == 0 {
		allowed, err := this.conf.Password.EmptyAllowed.Render(req)
		if err != nil {
			return failf("cannot evaluate of user is allowed for empty passwords: %w", err)
		}
		if !allowed {
			req.Logger().Debug("empty passwords are disabled for local user")
			return false, nil
		}
	}

	return true, nil
}

func (this *LocalAuthorizer) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	failf := func(t errors.Type, msg string, args ...any) (Authorization, error) {
		args = append([]any{sess}, args...)
		return nil, errors.Newf(t, "cannot restore authorization from session %v: "+msg, args...)
	}
	cleanFromSessionOnly := func() (Authorization, error) {
		if opts.IsAutoCleanUpAllowed() {
			// Clear the stored token.
			if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
				return failf(errors.System, "cannot clear existing authorization token of session after user wasn't found: %w", err)
			}
			opts.GetLogger(this.logger).
				With("session", sess).
				Info("session's user does not longer exist; therefore according authorization token was removed from session")
		}
		return nil, ErrNoSuchAuthorization
	}

	if !sess.Flow().IsEqualTo(this.flow) {
		return nil, ErrNoSuchAuthorization
	}

	tb, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve token: %w", err)
	}

	if len(tb) == 0 {
		return nil, ErrNoSuchAuthorization
	}

	var buf localToken
	if err := json.Unmarshal(tb, &buf); err != nil {
		return failf(errors.System, "cannot decode token of: %w", err)
	}

	var u *user.User
	if v := buf.User.Name; v != "" {
		if u, err = this.userRepository.LookupByName(ctx, v); errors.Is(err, user.ErrNoSuchUser) {
			return cleanFromSessionOnly()
		} else if err != nil {
			return failf(errors.System, "cannot lookup user by name %q: %w", v, err)
		}
	} else if v := buf.User.Uid; v != nil {
		if u, err = this.userRepository.LookupById(ctx, *v); errors.Is(err, user.ErrNoSuchUser) {
			return cleanFromSessionOnly()
		} else if err != nil {
			return failf(errors.System, "cannot lookup user by id %v: %w", *v, err)
		}
	} else {
		return nil, ErrNoSuchAuthorization
	}

	si, err := sess.Info(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's info: %w", err)
	}
	sla, err := si.LastAccessed(ctx)
	if err != nil {
		return failf(errors.System, "cannot retrieve session's last accessed: %w", err)
	}

	return &local{
		u,
		sla.Remote(),
		buf.EnvVars.Clone(),
		this.flow.Clone(),
		sess,
		nil,
	}, nil
}

func (this *LocalAuthorizer) Close() error {
	return this.userRepository.Close()
}

func (this *LocalAuthorizer) checkPasswordViaRepository(req PasswordRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	pass := req.RemotePassword()
	return this.checkPasswordValueViaRepository(req, pass, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) checkInteractiveViaRepository(req InteractiveRequest, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	pass, err := req.Prompt("Password: ", false)
	if err != nil {
		return "", nil, false, err
	}

	return this.checkPasswordValueViaRepository(req, pass, requestedUsername, validatePassword)
}

func (this *LocalAuthorizer) checkPasswordValueViaRepository(req Request, requestedPassword, requestedUsername string, validatePassword func(string, Request) (bool, error)) (username string, env sys.EnvVars, success bool, rErr error) {
	ok, err := validatePassword(requestedPassword, req)
	if err != nil || !ok {
		return "", nil, false, err
	}

	if ok, err := this.userRepository.ValidatePasswordByName(req.Context(), requestedUsername, requestedPassword); err != nil || !ok {
		return "", nil, false, err
	}

	return requestedUsername, nil, true, nil
}

func (this *LocalAuthorizer) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
