package authorization

import (
	"bytes"
	"context"
	"fmt"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/engity-com/yasshd/pkg/crypto"
	"github.com/engity-com/yasshd/pkg/errors"
	"github.com/engity-com/yasshd/pkg/template"
	"github.com/engity-com/yasshd/pkg/user"
	"golang.org/x/crypto/ssh"
)

type LocalAuthorizer struct {
	flow configuration.FlowName
	conf *configuration.AuthorizationLocal
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

	result := LocalAuthorizer{
		flow: flow,
		conf: conf,
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
		return Forbidden(), nil
	}

	u, err := user.Lookup(req.Remote().User())
	if err != nil {
		return failf("cannot lookup user: %w", err)
	}
	if u == nil {
		req.Logger().Debug("local user not found")
		return Forbidden(), nil
	}

	files, err := this.getAuthorizedKeysFilesOf(req, u)
	if err != nil {
		return failf("cannot get authorized keys files of user: %w", err)
	}
	if len(files) == 0 {
		req.Logger().Debug("local user does not has any authorized keys file")
		return Forbidden(), nil
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
		return Forbidden(), nil
	}

	return &Local{
		User: u,
		flow: this.flow,
	}, nil
}

func (this *LocalAuthorizer) getAuthorizedKeysFilesOf(req PublicKeyRequest, u *user.User) ([]string, error) {
	ctx := authorizedKeysRequestContext{req, u}
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
		return Forbidden(), nil
	}

	u, err := user.Lookup(req.Remote().User())
	if err != nil {
		return failf("cannot lookup user: %w", err)
	}
	if u == nil {
		req.Logger().Debug("local user not found")
		return Forbidden(), nil
	}

	rc := passwordRequestContext{req, u}

	allowed, err := this.conf.Password.Allowed.Render(rc)
	if err != nil {
		return failf("cannot evaluate of user is allowed: %w", err)
	}
	if !allowed {
		req.Logger().Debug("passwords are disabled for local user")
		return Forbidden(), nil
	}

	ok, err := this.checkPassword(req, u, this.validatePassword)
	if err != nil {
		return failf("cannot validate password: %w", err)
	}
	if !ok {
		return Forbidden(), nil
	}

	return &Local{u, this.flow}, nil
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
		return Forbidden(), nil
	}

	u, err := user.Lookup(req.Remote().User())
	if err != nil {
		return failf("cannot lookup user: %w", err)
	}
	if u == nil {
		req.Logger().Debug("local user not found")
		return Forbidden(), nil
	}

	rc := interactiveRequestContext{req, u}

	allowed, err := this.conf.Password.Allowed.Render(rc)
	if err != nil {
		return failf("cannot evaluate of user is allowed: %w", err)
	}
	if !allowed {
		req.Logger().Debug("passwords are disabled for local user")
		return Forbidden(), nil
	}

	ok, err := this.checkInteractive(req, u, this.validatePassword)
	if err != nil {
		return failf("cannot validate password: %w", err)
	}
	if !ok {
		return Forbidden(), nil
	}

	return &Local{u, this.flow}, nil
}

func (this *LocalAuthorizer) validatePassword(u *user.User, password string, req Request) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(message string, args ...any) (bool, error) {
		return fail(fmt.Errorf(message, args...))
	}

	if len(password) == 0 {
		rc := requestContext{req, u}
		allowed, err := this.conf.Password.EmptyAllowed.Render(rc)
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

type requestContext struct {
	Request
	User *user.User
}

type passwordRequestContext struct {
	PasswordRequest
	User *user.User
}

type authorizedKeysRequestContext struct {
	PublicKeyRequest
	User *user.User
}

type interactiveRequestContext struct {
	InteractiveRequest
	User *user.User
}
