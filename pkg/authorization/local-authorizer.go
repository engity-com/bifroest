package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/user"
	"golang.org/x/crypto/ssh"
)

type LocalAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationLocal

	userRepository user.CloseableRepository
}

func NewLocal(_ context.Context, flow configuration.FlowName, conf *configuration.AuthorizationLocal) (*LocalAuthorizer, error) {
	fail := func(err error) (*LocalAuthorizer, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*LocalAuthorizer, error) {
		return fail(errors.Newf(errors.TypeConfig, msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	userRepository, err := user.DefaultRepositoryProvider.Create()
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

func (this *LocalAuthorizer) AuthorizeSession(req SessionRequest) (Authorization, error) {
	sess := req.Session()
	if sess == nil {
		return Forbidden(req.Remote()), nil
	}

	fail := func(err error) (Authorization, error) {
		return nil, errors.Newf(errors.TypeSystem, "cannot authorize via existing session's authorization token: %w", err)
	}

	at, err := sess.AuthorizationToken()
	if err != nil {
		return fail(err)
	}
	if len(at) == 0 {
		return Forbidden(req.Remote()), nil
	}

	var buf localToken
	if err := json.Unmarshal(at, &buf); err != nil {
		return fail(err)
	}
	req.Logger().Debug("session restored")

	var u *user.User
	if v := buf.User.Uid; v != nil {
		if u, err = this.userRepository.LookupById(*v); err != nil {
			return fail(err)
		}
	} else if v := buf.User.Name; v != "" {
		if u, err = this.userRepository.LookupByName(v); err != nil {
			return fail(err)
		}
	} else {
		return Forbidden(req.Remote()), nil
	}

	return &Local{
		u,
		req.Remote(),
		nil,
		this.flow,
	}, nil

	return Forbidden(req.Remote()), nil
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

	u, err := this.userRepository.LookupByName(req.Remote().User())
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Debug("local user not found")
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user: %w", err)
	}

	files, err := this.getAuthorizedKeysFilesOf(req, u)
	if err != nil {
		return failf("cannot get authorized keys files of user: %w", err)
	}
	if len(files) == 0 {
		req.Logger().Debug("local user does not has any authorized keys file")
		return Forbidden(req.Remote()), nil
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
		return Forbidden(req.Remote()), nil
	}

	return &Local{
		u,
		req.Remote(),
		nil,
		this.flow,
	}, nil
}

func (this *LocalAuthorizer) getAuthorizedKeysFilesOf(req PublicKeyRequest, u *user.User) ([]string, error) {
	ctx := AuthorizedKeysRequestContext{req, u}
	return common.MapSliceErr(this.conf.AuthorizedKeys, func(tmpl template.String) (string, error) {
		return tmpl.Render(&ctx)
	})
}

func (this *LocalAuthorizer) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize local %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if this.conf.Password.Allowed.IsHardCodedFalse() {
		req.Logger().Debug("passwords disabled for local user")
		return Forbidden(req.Remote()), nil
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

	u, err := this.userRepository.LookupByName(username)
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Warn("local user %q not found; but it was just resolve before", username)
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user %q: %w", username, err)
	}

	return &Local{u, req.Remote(), ev, this.flow}, nil
}

func (this *LocalAuthorizer) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	fail := func(err error) (Authorization, error) {
		return nil, fmt.Errorf("cannot authorize local %q via password: %w", req.Remote().User(), err)
	}
	failf := func(message string, args ...any) (Authorization, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if this.conf.Password.InteractiveAllowed.IsHardCodedFalse() {
		req.Logger().Debug("passwords disabled for local user")
		return Forbidden(req.Remote()), nil
	}

	allowed, err := this.conf.Password.Allowed.Render(req)
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

	u, err := this.userRepository.LookupByName(username)
	if errors.Is(err, user.ErrNoSuchUser) {
		req.Logger().Warn("local user %q not found; but it was just resolve before", username)
		return Forbidden(req.Remote()), nil
	}
	if err != nil {
		return failf("cannot lookup user %q: %w", username, err)
	}

	return &Local{u, req.Remote(), ev, this.flow}, nil
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

func (this *LocalAuthorizer) Close() error {
	return this.userRepository.Close()
}

type AuthorizedKeysRequestContext struct {
	PublicKeyRequest
	User *user.User
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

	if ok, err := this.userRepository.ValidatePasswordByName(requestedUsername, requestedPassword); err != nil || !ok {
		return "", nil, false, err
	}

	return requestedUsername, nil, true, nil
}
