package environment

import (
	"context"
	"testing"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/stretchr/testify/require"
)

func TestLocalLoginGateAndRepositoryUseTheSameDecision(t *testing.T) {
	for _, value := range []bool{true, false} {
		conf := &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{LoginAllowed: template.BoolOf(value)}}
		ctx := targetTestContext{ctx: t.Context()}
		direct, err := LocalLoginAllowed(ctx, conf)
		require.NoError(t, err)
		require.Equal(t, value, direct)
		fromRepository, err := (&LocalRepository{conf: conf}).WillBeAccepted(ctx)
		require.NoError(t, err)
		require.Equal(t, direct, fromRepository)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conf := &configuration.EnvironmentLocal{EnvironmentLocalCommon: configuration.EnvironmentLocalCommon{LoginAllowed: template.BoolOf(true)}}
	// Admission is only a policy predicate. Sharing it must not introduce a
	// different cancellation order into the native repository's existing path.
	direct, err := LocalLoginAllowed(targetTestContext{ctx: ctx}, conf)
	require.NoError(t, err)
	fromRepository, err := (&LocalRepository{conf: conf}).WillBeAccepted(targetTestContext{ctx: ctx})
	require.NoError(t, err)
	require.Equal(t, direct, fromRepository)
	_, err = LocalLoginAllowed(nil, conf)
	require.True(t, errors.System.IsErr(err))
}
