package authorization

import (
	"context"
	goerrors "errors"
	"reflect"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

// FlowAuthorizerFactory supplies one flow's authentication dependency. It must
// not mutate the configuration and must release its own resources on failure.
// On success, the facade owns the returned authorizer and closes it.
type FlowAuthorizerFactory func(context.Context, *configuration.Flow) (DiscoveryAuthorizer, error)

// NewAuthorizerFacadeWithFactory preserves the production selection, requirements,
// HTTP pinning, response validation and observer path while allowing a caller to
// supply authentication dependencies without initializing the registered runtime
// authorizers. The factory is local to this facade; no global registration or
// request-controlled switch is changed. It must reject unsupported dependencies
// rather than substituting successful authentication.
//
// This constructor alone is not an offline runner: the supplied authorizers,
// requests, validators and session repositories define their own I/O boundaries.
func NewAuthorizerFacadeWithFactory(ctx context.Context, flows *configuration.Flows, factory FlowAuthorizerFactory, observer FlowAuthorizationObserver) (_ *AuthorizerFacade, resultErr error) {
	if factory == nil {
		return nil, errors.Config.Newf("authorization factory is required")
	}
	if flows == nil {
		return &AuthorizerFacade{observer: observer}, nil
	}

	entries := make([]facaded, len(*flows))
	initialized := 0
	defer func() {
		if resultErr == nil {
			return
		}
		for index := initialized - 1; index >= 0; index-- {
			resultErr = goerrors.Join(resultErr, entries[index].Close())
		}
	}()
	for index, flow := range *flows {
		if err := entries[index].newFrom(ctx, &flow, factory); err != nil {
			return nil, err
		}
		initialized++
	}

	return &AuthorizerFacade{entries: entries, flows: append(configuration.Flows(nil), (*flows)...), observer: observer}, nil
}

func newRegisteredFlowAuthorizer(ctx context.Context, flow *configuration.Flow) (DiscoveryAuthorizer, error) {
	factory, ok := configurationTypeToAuthorizerFactory[reflect.TypeOf(flow.Authorization.V)]
	if !ok {
		return nil, errors.Config.Newf("cannot handle authorization type %v", reflect.TypeOf(flow.Authorization.V))
	}
	rets := reflect.ValueOf(factory).Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(flow.Name), reflect.ValueOf(flow.Authorization.V)})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return nil, err
	}
	authorizer, ok := rets[0].Interface().(DiscoveryAuthorizer)
	if !ok {
		return nil, errors.Config.Newf("authorizer does not provide authentication capabilities")
	}
	return authorizer, nil
}
