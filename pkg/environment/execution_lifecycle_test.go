package environment

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestSignalFromSshRejectsUnknownSignal(t *testing.T) {
	_, err := signalFromSsh(essh.Signal("definitely-unknown"))
	require.ErrorIs(t, err, sys.ErrUnknownSignal)
}

func TestSignalFromSshPreservesKnownSignal(t *testing.T) {
	actual, err := signalFromSsh(essh.Signal("TERM"))
	require.NoError(t, err)
	require.Equal(t, sys.SIGTERM, actual)
}

func TestSignalProcessFromSshDoesNotSendUnknownSignal(t *testing.T) {
	called := false
	err := signalProcessFromSsh(essh.Signal("definitely-unknown"), func(sys.Signal) error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, sys.ErrUnknownSignal)
	require.False(t, called)
}

func TestSignalProcessFromSshSendsKnownSignal(t *testing.T) {
	var actual sys.Signal
	err := signalProcessFromSsh(essh.SIGTERM, func(signal sys.Signal) error {
		actual = signal
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, sys.SIGTERM, actual)
}

func TestSetReservedEnvironmentCanonicalizesWindowsAliases(t *testing.T) {
	environment := sys.EnvVars{
		"bifroest_connection_id": "attacker",
		"Bifroest_Execution_Id":  "attacker",
		session.EnvName:          "attacker",
		"bifroest_session_id":    "also-attacker",
		"UNCHANGED":              "value",
	}
	setReservedEnvironment(&environment, sys.OsWindows,
		connection.EnvName, "trusted-connection",
		execution.EnvName, "trusted-execution",
		session.EnvName, "trusted-session",
	)

	require.Equal(t, sys.EnvVars{
		connection.EnvName: "trusted-connection",
		execution.EnvName:  "trusted-execution",
		session.EnvName:    "trusted-session",
		"UNCHANGED":        "value",
	}, environment)
}

func TestAttachDockerExecWithTimeoutBoundsApiSetup(t *testing.T) {
	started := time.Now()
	_, err := attachDockerExecWithTimeout(context.Background(), 20*time.Millisecond, func(ctx context.Context) (types.HijackedResponse, error) {
		<-ctx.Done()
		return types.HijackedResponse{}, ctx.Err()
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestAttachDockerExecWithTimeoutReturnsApiResult(t *testing.T) {
	want := errors.New("attach failed")
	_, err := attachDockerExecWithTimeout(context.Background(), time.Second, func(ctx context.Context) (types.HijackedResponse, error) {
		require.NoError(t, ctx.Err())
		return types.HijackedResponse{}, want
	})
	require.ErrorIs(t, err, want)
}

func TestAttachDockerExecWithTimeoutDoesNotCancelOutputSetupWithTask(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want := errors.New("attach completed")
	_, err := attachDockerExecWithTimeout(ctx, time.Second, func(ctx context.Context) (types.HijackedResponse, error) {
		require.NoError(t, ctx.Err())
		return types.HijackedResponse{}, want
	})
	require.ErrorIs(t, err, want)
}

func TestScheduleDockerExecutionCleanupRetriesWithoutBlockingCaller(t *testing.T) {
	executionId := connection.MustNewId()
	completed := make(chan struct{})
	var attempts atomic.Int32
	started := time.Now()
	scheduleDockerExecutionCleanup(nil, executionId, func(ctx context.Context) error {
		require.NoError(t, ctx.Err())
		if attempts.Add(1) < 3 {
			return imp.ErrNoSuchProcess
		}
		close(completed)
		return nil
	})
	require.Less(t, time.Since(started), 100*time.Millisecond)
	require.Eventually(t, func() bool {
		select {
		case <-completed:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, int32(3), attempts.Load())
}

func TestWaitForKubernetesExecutionExitCodePassesDeadlineToRpc(t *testing.T) {
	executionId, err := execution.NewId()
	require.NoError(t, err)
	started := time.Now()
	_, err = waitForKubernetesExecutionExitCode(context.Background(), executionId, 30*time.Millisecond, func(ctx context.Context, actual execution.Id) (int, error) {
		require.Equal(t, executionId, actual)
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), 30*time.Millisecond)
		<-ctx.Done()
		return 0, ctx.Err()
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), time.Second)
}

func TestRetryExecutionSignalWaitsForProcessRegistration(t *testing.T) {
	var attempts atomic.Int32
	err := retryExecutionSignal(context.Background(), func(context.Context) error {
		if attempts.Add(1) < 3 {
			return imp.ErrNoSuchProcess
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, int32(3), attempts.Load())
}

func TestRetryExecutionSignalStopsOnOtherErrors(t *testing.T) {
	want := errors.New("signal failed")
	err := retryExecutionSignal(context.Background(), func(context.Context) error { return want })
	require.ErrorIs(t, err, want)
}

func TestCleanupKubernetesExecutionForcesAfterGracefulFailure(t *testing.T) {
	var signals []sys.Signal
	gracefulErr, forceErr := cleanupKubernetesExecution(context.Background(), 20*time.Millisecond, time.Millisecond, 20*time.Millisecond, sys.SIGINT, func(_ context.Context, signal sys.Signal) error {
		signals = append(signals, signal)
		if signal == sys.SIGINT {
			return imp.ErrNoSuchProcess
		}
		return nil
	})

	require.ErrorIs(t, gracefulErr, context.DeadlineExceeded)
	require.NoError(t, forceErr)
	require.NotEmpty(t, signals)
	require.Equal(t, sys.SIGKILL, signals[len(signals)-1])
}

func TestCleanupKubernetesExecutionForcesAfterPermanentGracefulError(t *testing.T) {
	want := errors.New("graceful signal failed")
	var signals []sys.Signal
	gracefulErr, forceErr := cleanupKubernetesExecution(context.Background(), time.Second, time.Millisecond, time.Second, sys.SIGTERM, func(_ context.Context, signal sys.Signal) error {
		signals = append(signals, signal)
		if signal == sys.SIGTERM {
			return want
		}
		return nil
	})

	require.ErrorIs(t, gracefulErr, want)
	require.NoError(t, forceErr)
	require.Equal(t, []sys.Signal{sys.SIGTERM, sys.SIGKILL}, signals)
}
