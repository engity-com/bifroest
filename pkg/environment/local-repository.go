package environment

import (
	"context"
	"fmt"
)

var (
	_ = RegisterRepository(NewLocalRepository)
)

func (this *LocalRepository) WillBeAccepted(ctx Context) (ok bool, err error) {
	_, ok, err = this.willBeAccepted(ctx)
	return ok, err
}

func (this *LocalRepository) willBeAccepted(ctx Context) (target any, ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if target, ok, err = this.resolveTargetAccount(ctx); err != nil || !ok {
		return target, ok, err
	}

	if ok, err = this.conf.LoginAllowed.Render(withTargetAccount(ctx, target)); err != nil {
		ok, err = fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
		return target, ok, err
	}

	return target, ok, nil
}

type targetAccountContext struct {
	targetAccountParentContext
	targetAccount any
}

type targetAccountParentContext interface {
	Context
}

func withTargetAccount(ctx Context, target any) Context {
	if target == nil {
		return ctx
	}
	return &targetAccountContext{targetAccountParentContext: ctx, targetAccount: target}
}

func (this *targetAccountContext) GetField(name string) (any, bool, error) {
	if name == "targetAccount" {
		return this.targetAccount, true, nil
	}
	if parent, ok := this.targetAccountParentContext.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return parent.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}

type targetAccountRequest struct {
	Request
	targetAccount any
}

func withTargetAccountRequest(req Request, target any) Request {
	if target == nil {
		return req
	}
	return &targetAccountRequest{Request: req, targetAccount: target}
}

func (this *targetAccountRequest) GetField(name string) (any, bool, error) {
	if name == "targetAccount" {
		return this.targetAccount, true, nil
	}
	if parent, ok := this.Request.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return parent.GetField(name)
	}
	return nil, false, fmt.Errorf("unknown field %q", name)
}

func (this *LocalRepository) Cleanup(context.Context, *CleanupOpts) error {
	return nil
}
