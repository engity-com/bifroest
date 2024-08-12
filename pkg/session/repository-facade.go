package session

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/configuration"
	"reflect"
)

func NewRepositoryFacade(ctx context.Context, conf *configuration.Session) (*RepositoryFacade, error) {
	if conf == nil {
		panic("nil configuration")
	}
	instance, err := newRepositoryInstance(ctx, conf)
	if err != nil {
		return nil, err
	}
	return &RepositoryFacade{instance}, nil
}

type RepositoryFacade struct {
	CloseableRepository
}

func newRepositoryInstance(_ context.Context, conf *configuration.Session) (r CloseableRepository, err error) {
	fail := func(err error) (CloseableRepository, error) {
		return nil, fmt.Errorf("cannot initizalize session repository: %w", err)
	}

	switch sessConv := conf.V.(type) {
	case *configuration.SessionSimple:
		r, err = NewSimpleRepository(sessConv)
	case *configuration.SessionFs:
		r, err = NewFsRepository(sessConv)
	default:
		return fail(fmt.Errorf("cannot handle session type %v", reflect.TypeOf(conf.V)))
	}

	if err != nil {
		return fail(fmt.Errorf("cannot initizalize session repository: %w", err))
	}
	return r, nil
}
