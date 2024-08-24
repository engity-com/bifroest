package authorization

import (
	"context"
	"fmt"
	"reflect"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func NewAuthorizerFacade(ctx context.Context, flows *configuration.Flows) (*AuthorizerFacade, error) {
	if flows == nil {
		return &AuthorizerFacade{}, nil
	}

	entries := make([]facaded, len(*flows))
	for i, flow := range *flows {
		if err := entries[i].newFrom(ctx, &flow); err != nil {
			return nil, err
		}
	}

	return &AuthorizerFacade{entries}, nil
}

type AuthorizerFacade struct {
	entries []facaded
}

func (this *AuthorizerFacade) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
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
	return Forbidden(req.Remote()), nil
}

func (this *AuthorizerFacade) AuthorizePassword(req PasswordRequest) (Authorization, error) {
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
	return Forbidden(req.Remote()), nil
}

func (this *AuthorizerFacade) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
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
	return Forbidden(req.Remote()), nil
}

func (this *AuthorizerFacade) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	for _, candidate := range this.entries {
		auth, err := candidate.RestoreFromSession(ctx, sess, opts)
		if errors.Is(err, ErrNoSuchAuthorization) {
			continue
		}
		if err != nil {
			return auth, fmt.Errorf("[%v] %w", candidate.flow, err)
		}
		return auth, nil
	}
	return nil, ErrNoSuchAuthorization
}

func (this *AuthorizerFacade) Close() (rErr error) {
	defer func() { this.entries = nil }()
	for _, candidate := range this.entries {
		defer common.KeepCloseError(&rErr, candidate)
	}
	return nil
}

type facaded struct {
	CloseableAuthorizer

	flow        configuration.FlowName
	requirement *configuration.Requirement
}

func (this *facaded) newFrom(ctx context.Context, flow *configuration.Flow) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot initizalize authorization for flow %q: %w", flow.Name, err)
	}

	factory, ok := configurationTypeToAuthorizerFactory[reflect.TypeOf(flow.Authorization.V)]
	if !ok {
		return fail(errors.Config.Newf("cannot handle authorization type %v", reflect.TypeOf(flow.Authorization.V)))
	}
	m := reflect.ValueOf(factory)
	rets := m.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(flow.Name), reflect.ValueOf(flow.Authorization.V)})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return fail(err)
	}
	this.CloseableAuthorizer = rets[0].Interface().(CloseableAuthorizer)
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

var (
	configurationTypeToAuthorizerFactory = make(map[reflect.Type]any)
)

type AuthorizerFactory[C any, A CloseableAuthorizer] func(ctx context.Context, flow configuration.FlowName, conf C) (A, error)

func RegisterAuthorizer[C any, A CloseableAuthorizer](factory AuthorizerFactory[C, A]) AuthorizerFactory[C, A] {
	ct := reflect.TypeFor[C]()
	configurationTypeToAuthorizerFactory[ct] = factory
	return factory
}
