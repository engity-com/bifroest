package session

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"reflect"
	"unsafe"
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
	instance, err := factory(ctx, conf.V)
	if err != nil {
		return fail(err)
	}

	return instance, nil
}

var (
	configurationTypeToRepositoryFactory map[reflect.Type]RepositoryFactory[any, CloseableRepository]
)

type RepositoryFactory[C any, R CloseableRepository] func(ctx context.Context, conf C) (R, error)

func RegisterRepository[C any, R CloseableRepository](factory RepositoryFactory[C, R]) RepositoryFactory[C, R] {
	ct := reflect.TypeFor[C]()
	configurationTypeToRepositoryFactory[ct] = *(*RepositoryFactory[any, CloseableRepository])(unsafe.Pointer(&factory))
	return factory
}
