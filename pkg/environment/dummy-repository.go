package environment

import (
	"context"

	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterRepository(NewDummyRepository)
)

func NewDummyRepository(_ context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDummy, _ alternatives.Provider, _ imp.Imp) (*DummyRepository, error) {
	return &DummyRepository{
		flow: flow,
		conf: conf,
	}, nil
}

type DummyRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentDummy
}

func (this *DummyRepository) WillBeAccepted(_ Context) (bool, error) {
	return true, nil
}

func (this *DummyRepository) DoesSupportPty(_ Context, _ ssh.Pty) (bool, error) {
	return true, nil
}

func (this *DummyRepository) Ensure(req Request) (Environment, error) {
	sess := req.Authorization().FindSession()
	if sess == nil {
		return nil, errors.System.Newf("authorization without session")
	}
	return this.FindBySession(req.Context(), sess, nil)
}

func (this *DummyRepository) FindBySession(_ context.Context, sess session.Session, _ *FindOpts) (Environment, error) {
	return &dummy{this, sess}, nil
}

func (this *DummyRepository) Close() error {
	return nil
}
