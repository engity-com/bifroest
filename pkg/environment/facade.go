package environment

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"io"
	"reflect"
)

func NewFacade(ctx context.Context, flows *configuration.Flows) (*Facade, error) {
	if flows == nil {
		return &Facade{}, nil
	}

	entries := make(map[configuration.FlowName]CloseableEnvironment, len(*flows))
	for _, flow := range *flows {
		instance, err := newInstance(ctx, &flow)
		if err != nil {
			return nil, err
		}
		entries[flow.Name] = instance
	}

	return &Facade{entries}, nil
}

type Facade struct {
	entries map[configuration.FlowName]CloseableEnvironment
}

func (this *Facade) WillBeAccepted(req Request) (bool, error) {
	flow := req.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.WillBeAccepted(req)
}

func (this *Facade) Banner(req Request) (io.ReadCloser, error) {
	flow := req.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return nil, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.Banner(req)
}

func (this *Facade) Run(t Task) error {
	flow := t.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.Run(t)
}

func (this *Facade) Close() (rErr error) {
	for _, entity := range this.entries {
		defer common.KeepCloseError(&rErr, entity)
	}
	return nil
}

func newInstance(_ context.Context, flow *configuration.Flow) (env CloseableEnvironment, err error) {
	fail := func(err error) (CloseableEnvironment, error) {
		return nil, fmt.Errorf("cannot initizalize environment for flow %q: %w", flow.Name, err)
	}

	switch envConf := flow.Environment.V.(type) {
	case *configuration.EnvironmentLocal:
		env, err = NewLocal(flow.Name, envConf)
	default:
		return fail(fmt.Errorf("cannot handle environment type %v", reflect.TypeOf(flow.Authorization.V)))
	}

	if err != nil {
		return fail(fmt.Errorf("cannot initizalize environment for flow %q: %w", flow.Name, err))
	}
	return env, nil
}
