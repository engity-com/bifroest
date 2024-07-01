package environment

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"reflect"
)

func NewRepositoryFacade(ctx context.Context, flows *configuration.Flows) (*RepositoryFacade, error) {
	if flows == nil {
		return &RepositoryFacade{}, nil
	}

	entries := make(map[configuration.FlowName]CloseableRepository, len(*flows))
	for _, flow := range *flows {
		instance, err := newInstance(ctx, &flow)
		if err != nil {
			return nil, err
		}
		entries[flow.Name] = instance
	}

	return &RepositoryFacade{entries}, nil
}

type RepositoryFacade struct {
	entries map[configuration.FlowName]CloseableRepository
}

func (this *RepositoryFacade) WillBeAccepted(req Request) (bool, error) {
	flow := req.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.WillBeAccepted(req)
}

func (this *RepositoryFacade) Ensure(req Request) (Environment, error) {
	flow := req.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return nil, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.Ensure(req)
}

func (this *RepositoryFacade) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	flow := sess.Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return nil, ErrNoSuchEnvironment
	}
	return candidate.FindBySession(ctx, sess, opts)
}

func (this *RepositoryFacade) Close() (rErr error) {
	for _, entity := range this.entries {
		defer common.KeepCloseError(&rErr, entity)
	}
	return nil
}

func newInstance(ctx context.Context, flow *configuration.Flow) (env CloseableRepository, err error) {
	fail := func(err error) (CloseableRepository, error) {
		return nil, fmt.Errorf("cannot initizalize environment for flow %q: %w", flow.Name, err)
	}

	switch envConf := flow.Environment.V.(type) {
	case *configuration.EnvironmentLocal:
		env, err = NewLocalRepository(ctx, flow.Name, envConf)
	default:
		return fail(fmt.Errorf("cannot handle environment type %v", reflect.TypeOf(flow.Authorization.V)))
	}

	if err != nil {
		return fail(fmt.Errorf("cannot initizalize environment for flow %q: %w", flow.Name, err))
	}
	return env, nil
}
