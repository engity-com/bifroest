package environment

import (
	"context"
	"fmt"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterRepository(NewDummyRepository)
)

type DummyRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentDummy

	Logger log.Logger
}

func NewDummyRepository(_ context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDummy) (*DummyRepository, error) {
	fail := func(err error) (*DummyRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*DummyRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := DummyRepository{
		flow: flow,
		conf: conf,
	}

	return &result, nil
}

func (this *DummyRepository) WillBeAccepted(req Request) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(req); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *DummyRepository) DoesSupportPty(Request, ssh.Pty) (bool, error) {
	return true, nil
}

func (this *DummyRepository) Ensure(req Request) (Environment, error) {
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

	return this.FindBySession(req.Context(), sess, nil)
}

func (this *DummyRepository) FindBySession(_ context.Context, sess session.Session, _ *FindOpts) (Environment, error) {
	return &dummy{
		this,
		sess,
	}, nil
}

func (this *DummyRepository) Close() error {
	return nil
}
