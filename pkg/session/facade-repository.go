package session

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"reflect"
)

func NewFacadeRepository(ctx context.Context, conf *configuration.Session) (*FacadeRepository, error) {
	if conf == nil {
		panic("nil configuration")
	}
	instance, err := newRepositoryInstance(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &FacadeRepository{instance}, nil
}

type FacadeRepository struct {
	CloseableRepository
}

func newRepositoryInstance(ctx context.Context, conf *configuration.Session) (CloseableRepository, error) {
	fail := func(err error) (CloseableRepository, error) {
		return nil, fmt.Errorf("cannot initizalize session repository: %w", err)
	}

	if conf.V == nil {
		return fail(errors.Config.Newf("no session configured"))
	}

	factory, ok := configurationTypeToRepositoryFactory[reflect.TypeOf(conf.V)]
	if !ok {
		return fail(errors.Config.Newf("cannot handle session type %v", reflect.TypeOf(conf.V)))
	}
	m := reflect.ValueOf(factory)
	rets := m.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(conf.V)})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return fail(err)
	}
	return rets[0].Interface().(CloseableRepository), nil
}

var (
	configurationTypeToRepositoryFactory = make(map[reflect.Type]any)
)

type RepositoryFactory[C any, R CloseableRepository] func(ctx context.Context, conf C) (R, error)

func RegisterRepository[C any, R CloseableRepository](factory RepositoryFactory[C, R]) RepositoryFactory[C, R] {
	ct := reflect.TypeFor[C]()
	configurationTypeToRepositoryFactory[ct] = factory
	return factory
}
