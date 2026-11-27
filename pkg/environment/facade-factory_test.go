package environment

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp"
)

type facadeFactoryTestAlternatives struct {
	alternatives.Provider
	closes atomic.Int32
}

type facadePreparationTestRepository struct {
	CloseableRepository
	closes int
	err    error
}

func (this *facadePreparationTestRepository) Close() error {
	this.closes++
	return this.err
}

func TestFacadePreparationClosesPartialProvidersAndReportsCleanupFailure(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider-failure", true: "cancellation"}[canceled], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			cleanupErr := errors.New("injected provider close failure")
			preparationErr := errors.New("injected provider preparation failure")
			first := &facadePreparationTestRepository{err: cleanupErr}
			flows := configuration.Flows{{Name: "first"}, {Name: "second"}}
			calls := 0
			facade, err := newRepositoryFacadeUsing(ctx, &flows, nil, nil, func(context.Context, *configuration.Flow, alternatives.Provider, imp.Imp) (CloseableRepository, error) {
				calls++
				if calls == 1 {
					if canceled {
						cancel()
					}
					return first, nil
				}
				return nil, preparationErr
			})
			require.Nil(t, facade)
			require.ErrorIs(t, err, cleanupErr)
			if canceled {
				require.ErrorIs(t, err, context.Canceled)
				require.Equal(t, 1, calls)
			} else {
				require.ErrorIs(t, err, preparationErr)
				require.Equal(t, 2, calls)
			}
			require.Equal(t, 1, first.closes)
		})
	}
}

func (this *facadeFactoryTestAlternatives) Close() error { this.closes.Add(1); return nil }

type facadeFactoryTestImp struct {
	imp.Imp
	closes atomic.Int32
}

func (this *facadeFactoryTestImp) Close() error { this.closes.Add(1); return nil }

func TestFacadeFactorySharesLocalAccountCoordinatorAcrossGenerations(t *testing.T) {
	ap, i := &facadeFactoryTestAlternatives{}, &facadeFactoryTestImp{}
	// Inspect the dependencies passed to providers without accessing privileged
	// account databases. The same mutex guards local Ensure/Dispose calls.
	factory := NewFacadeFactory(ap, i, nil, nil)
	var conf configuration.EnvironmentDummy
	require.NoError(t, conf.SetDefaults())
	flows := configuration.Flows{{Name: "local", Environment: configuration.Environment{V: &conf}}}
	first, err := factory.NewWithManagement(context.Background(), &flows, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, first.Close()) })
	second, err := factory.NewWithManagement(context.Background(), &flows, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.Close()) })
	require.NotSame(t, first.entries["local"], second.entries["local"])
	one := repositoryDependenciesFrom(factory.contextFor(context.Background(), nil)).localAccounts
	two := repositoryDependenciesFrom(factory.contextFor(context.Background(), nil)).localAccounts
	require.Same(t, one, two)
	one.mu.Lock()
	entered, acquired := make(chan struct{}), make(chan struct{})
	go func() {
		close(entered)
		two.mu.Lock()
		close(acquired)
		two.mu.Unlock()
	}()
	<-entered
	select {
	case <-acquired:
		t.Error("separate generations did not share their account operation lock")
	case <-time.After(20 * time.Millisecond):
	}
	one.mu.Unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("shared coordinator did not unlock")
	}
	require.NoError(t, first.Close())
	require.NoError(t, second.Close())
	require.Zero(t, ap.closes.Load())
	require.Zero(t, i.closes.Load())
}
