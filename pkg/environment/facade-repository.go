package environment

import (
	"context"
	"fmt"
	"reflect"

	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

func NewRepositoryFacade(ctx context.Context, flows *configuration.Flows, i imp.Imp) (*RepositoryFacade, error) {
	if flows == nil {
		return &RepositoryFacade{}, nil
	}

	entries := make(map[configuration.FlowName]CloseableRepository, len(*flows))
	for _, flow := range *flows {
		instance, err := newInstance(ctx, &flow, i)
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

func (this *RepositoryFacade) WillBeAccepted(ctx Context) (bool, error) {
	flow := ctx.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.WillBeAccepted(ctx)
}

func (this *RepositoryFacade) DoesSupportPty(ctx Context, pty ssh.Pty) (bool, error) {
	flow := ctx.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.DoesSupportPty(ctx, pty)
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

func newInstance(ctx context.Context, flow *configuration.Flow, i imp.Imp) (env CloseableRepository, err error) {
	fail := func(err error) (CloseableRepository, error) {
		return nil, errors.System.Newf("cannot initizalize environment for flow %q: %w", flow.Name, err)
	}

	if flow.Environment.V == nil {
		return fail(errors.Config.Newf("no environment configured"))
	}

	factory, ok := configurationTypeToRepositoryFactory[reflect.TypeOf(flow.Environment.V)]
	if !ok {
		return fail(errors.Config.Newf("cannot handle environment type %v", reflect.TypeOf(flow.Environment.V)))
	}
	m := reflect.ValueOf(factory)
	rets := m.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(flow.Name), reflect.ValueOf(flow.Environment.V), reflect.ValueOf(i)})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return fail(err)
	}
	return rets[0].Interface().(CloseableRepository), nil
}

var (
	configurationTypeToRepositoryFactory = make(map[reflect.Type]any)
)

type RepositoryFactory[C any, R CloseableRepository] func(context.Context, configuration.FlowName, C, imp.Imp) (R, error)

func RegisterRepository[C any, R CloseableRepository](factory RepositoryFactory[C, R]) RepositoryFactory[C, R] {
	ct := reflect.TypeFor[C]()
	configurationTypeToRepositoryFactory[ct] = factory
	return factory
}
