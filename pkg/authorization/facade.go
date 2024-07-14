package authorization

import (
	"context"
	"fmt"
	"github.com/engity-com/yasshd/pkg/configuration"
	"reflect"
)

func NewFacade(ctx context.Context, flows *configuration.Flows) (*Facade, error) {
	if flows == nil {
		return &Facade{}, nil
	}

	entries := make([]facaded, len(*flows))
	for i, flow := range *flows {
		if err := entries[i].setConf(ctx, &flow); err != nil {
			return nil, err
		}
	}

	return &Facade{entries}, nil
}

type Facade struct {
	entries []facaded
}

func (this *Facade) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	for _, candidate := range this.entries {
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			if resp, err := candidate.AuthorizePublicKey(req); err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			} else if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	return Forbidden(), nil
}

func (this *Facade) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	for _, candidate := range this.entries {
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			if resp, err := candidate.AuthorizePassword(req); err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			} else if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	return Forbidden(), nil
}

func (this *Facade) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	for _, candidate := range this.entries {
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			if resp, err := candidate.AuthorizeInteractive(req); err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			} else if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	return Forbidden(), nil
}

type facaded struct {
	Authorizer

	flow        configuration.FlowName
	requirement *configuration.Requirement
}

func (this *facaded) setConf(ctx context.Context, flow *configuration.Flow) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot initizalize authorization for flow %q: %w", flow.Name, err)
	}

	switch authConf := flow.Authorization.V.(type) {
	case *configuration.AuthorizationOidcDeviceAuth:
		v, err := NewOidcDeviceAuth(ctx, flow.Name, authConf)
		if err != nil {
			return fail(err)
		}
		this.Authorizer = v
	default:
		return fail(fmt.Errorf("cannot handle authorization type %v", reflect.TypeOf(flow.Authorization.V)))
	}

	this.requirement = &flow.Requirement
	this.flow = flow.Name
	return nil
}

func (this *facaded) canHandle(req Request) (bool, error) {
	incl, excl := this.requirement.IncludedRequestingName, this.requirement.ExcludedRequestingName

	if !incl.IsZero() && !incl.MatchString(req.Remote().User()) {
		return false, nil
	}
	if !excl.IsZero() && excl.MatchString(req.Remote().User()) {
		return false, nil
	}

	return true, nil
}
