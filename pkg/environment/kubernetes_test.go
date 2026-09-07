package environment

import (
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	bkube "github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestWaitForKubernetesImpEnvironmentRetriesTemporaryFailure(t *testing.T) {
	attempts := 0
	expected := sys.EnvVars{"READY": "true"}
	actual, err := waitForKubernetesImpEnvironment(context.Background(), log.GetLogger("test"), time.Second, 3, 0, func(context.Context) (sys.EnvVars, error) {
		attempts++
		if attempts < 3 {
			return nil, bkube.ErrEndpointNotFound
		}
		return expected, nil
	})

	require.NoError(t, err)
	require.Equal(t, expected, actual)
	require.Equal(t, 3, attempts)
}

func TestWaitForKubernetesImpEnvironmentFailsAfterLastAttempt(t *testing.T) {
	attempts := 0
	actual, err := waitForKubernetesImpEnvironment(context.Background(), log.GetLogger("test"), time.Second, 2, 0, func(context.Context) (sys.EnvVars, error) {
		attempts++
		return nil, bkube.ErrEndpointNotFound
	})

	require.ErrorIs(t, err, bkube.ErrEndpointNotFound)
	require.Nil(t, actual)
	require.Equal(t, 2, attempts)
}

func TestWaitForKubernetesImpEnvironmentStopsOnNonRetryableError(t *testing.T) {
	expected := fmt.Errorf("readiness failed")
	attempts := 0
	_, err := waitForKubernetesImpEnvironment(context.Background(), log.GetLogger("test"), time.Second, 3, 0, func(context.Context) (sys.EnvVars, error) {
		attempts++
		return nil, expected
	})

	require.ErrorIs(t, err, expected)
	require.Equal(t, 1, attempts)
}

func TestWaitForKubernetesImpEnvironmentPreservesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, err := waitForKubernetesImpEnvironment(ctx, log.GetLogger("test"), time.Second, 3, time.Second, func(context.Context) (sys.EnvVars, error) {
		cancel()
		return nil, bkube.ErrEndpointNotFound
	})

	require.ErrorIs(t, err, context.Canceled)
}

func TestWaitForKubernetesImpEnvironmentBoundsRpcCall(t *testing.T) {
	_, err := waitForKubernetesImpEnvironment(context.Background(), log.GetLogger("test"), 20*time.Millisecond, 200, time.Second, func(ctx context.Context) (sys.EnvVars, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	require.ErrorIs(t, err, context.DeadlineExceeded)
}
