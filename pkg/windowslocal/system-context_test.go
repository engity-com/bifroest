package windowslocal

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestS4USystemContextChecksCallerWorkerAndCompletion(t *testing.T) {
	var inspected, actions atomic.Int32
	err := runS4USystemContext(t.Context(), func() error { inspected.Add(1); return nil }, func() error { actions.Add(1); return nil })
	require.NoError(t, err)
	require.EqualValues(t, 4, inspected.Load())
	require.EqualValues(t, 1, actions.Load())
}

func TestS4USystemContextRejectsIdentityFailureAtEachBoundary(t *testing.T) {
	for _, phase := range []int32{1, 2, 3, 4} {
		t.Run(string(rune('0'+phase)), func(t *testing.T) {
			var inspected, actions atomic.Int32
			failure := errors.New("identity changed")
			err := runS4USystemContext(t.Context(), func() error {
				if inspected.Add(1) == phase {
					return failure
				}
				return nil
			}, func() error { actions.Add(1); return nil })
			require.ErrorIs(t, err, failure)
			if phase < 3 {
				require.Zero(t, actions.Load())
			} else {
				require.EqualValues(t, 1, actions.Load())
			}
		})
	}
}

func TestS4USystemContextJoinsNativeWorkAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	t.Cleanup(func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	})
	done := make(chan error, 1)
	go func() {
		done <- runS4USystemContext(ctx, func() error { return nil }, func() error {
			defer close(cleaned)
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation abandoned native callback/cleanup")
	case <-time.After(30 * time.Millisecond):
	}
	released.Store(true)
	close(release)
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case <-cleaned:
	default:
		t.Fatal("result returned before native cleanup")
	}
}

func TestS4USystemContextRedactsPanicsAndRejectsAbnormalWorkerExit(t *testing.T) {
	for _, phase := range []string{"caller", "worker-inspect", "action", "worker-exit"} {
		t.Run(phase, func(t *testing.T) {
			var inspected atomic.Int32
			var cleaned atomic.Bool
			err := runS4USystemContext(t.Context(), func() error {
				n := inspected.Add(1)
				if phase == "caller" && n == 1 || phase == "worker-inspect" && n == 2 {
					panic("private native detail")
				}
				return nil
			}, func() error {
				defer cleaned.Store(true)
				if phase == "worker-exit" {
					runtime.Goexit()
				}
				panic("private native detail")
			})
			require.ErrorIs(t, err, errS4UNativeWorker)
			require.NotContains(t, err.Error(), "private native detail")
			if phase == "action" || phase == "worker-exit" {
				require.True(t, cleaned.Load())
			}
		})
	}
}

func TestS4USystemContextRejectsNilPanicsWithLegacyRuntimeSetting(t *testing.T) {
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",panicnil=1")
	for _, phase := range []int32{1, 2, 3, 4} {
		t.Run(string(rune('0'+phase)), func(t *testing.T) {
			var inspected atomic.Int32
			err := runS4USystemContext(t.Context(), func() error {
				if inspected.Add(1) == phase {
					panic(nil)
				}
				return nil
			}, func() error { return nil })
			require.ErrorIs(t, err, errS4UNativeWorker)
		})
	}
}

func TestS4USystemContextPreservesCancellationWithFinalCallerPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var inspected atomic.Int32
	err := runS4USystemContext(ctx, func() error {
		if inspected.Add(1) == 4 {
			cancel()
			panic("private native detail")
		}
		return nil
	}, func() error { return nil })
	require.ErrorIs(t, err, errS4UNativeWorker)
	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, err.Error(), "private native detail")
}

func TestS4USystemContextRequiresLiveContextAndCompleteOperations(t *testing.T) {
	var calls atomic.Int32
	inspect := func() error { calls.Add(1); return nil }
	action := func() error { calls.Add(1); return nil }
	require.Error(t, runS4USystemContext(nil, inspect, action))
	require.Error(t, runS4USystemContext(t.Context(), nil, action))
	require.Error(t, runS4USystemContext(t.Context(), inspect, nil))
	require.Error(t, runS4USystemContextOnThread(t.Context(), inspect, action, nil))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, runS4USystemContext(ctx, inspect, action), context.Canceled)
	require.Zero(t, calls.Load())
}

func TestS4USystemContextReservesStartupThreadBeforeNativeWork(t *testing.T) {
	var candidates, inspected, actions atomic.Int32
	err := runS4USystemContextOnThread(t.Context(), func() error { inspected.Add(1); return nil }, func() error { actions.Add(1); return nil }, func() (bool, error) { return candidates.Add(1) == 1, nil })
	require.NoError(t, err)
	require.EqualValues(t, 2, candidates.Load())
	require.EqualValues(t, 4, inspected.Load())
	require.EqualValues(t, 1, actions.Load())
}

func TestS4USystemContextRejectsFailedOrRepeatedStartupClassification(t *testing.T) {
	for _, scenario := range []string{"classifier-error", "repeated-startup", "cancel-before-handoff"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("thread identity unavailable")
			var candidates, inspected, actions atomic.Int32
			err := runS4USystemContextOnThread(ctx, func() error { inspected.Add(1); return nil }, func() error { actions.Add(1); return nil }, func() (bool, error) {
				candidates.Add(1)
				if scenario == "classifier-error" {
					return false, failure
				}
				if scenario == "cancel-before-handoff" {
					cancel()
				}
				return true, nil
			})
			require.Error(t, err)
			require.Zero(t, actions.Load())
			require.EqualValues(t, 1, inspected.Load())
			if scenario == "classifier-error" {
				require.ErrorIs(t, err, failure)
				require.EqualValues(t, 1, candidates.Load())
			}
			if scenario == "repeated-startup" {
				require.ErrorIs(t, err, errS4UNativeWorker)
				require.EqualValues(t, 2, candidates.Load())
			}
			if scenario == "cancel-before-handoff" {
				require.ErrorIs(t, err, context.Canceled)
				require.EqualValues(t, 1, candidates.Load())
			}
		})
	}
}

func TestS4USystemContextStartupHandoffPreservesChildFailureAndCleanup(t *testing.T) {
	for _, failure := range []string{"panic", "goexit"} {
		t.Run(failure, func(t *testing.T) {
			var candidates atomic.Int32
			var cleaned atomic.Bool
			err := runS4USystemContextOnThread(t.Context(), func() error { return nil }, func() error {
				defer cleaned.Store(true)
				if failure == "goexit" {
					runtime.Goexit()
				}
				panic("private child detail")
			}, func() (bool, error) { return candidates.Add(1) == 1, nil })
			require.ErrorIs(t, err, errS4UNativeWorker)
			require.NotContains(t, err.Error(), "private child detail")
			require.True(t, cleaned.Load())
			require.EqualValues(t, 2, candidates.Load())
		})
	}
}

func TestS4USystemContextStartupHandoffJoinsCanceledChild(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var released atomic.Bool
	t.Cleanup(func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	})
	var candidates atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- runS4USystemContextOnThread(ctx, func() error { return nil }, func() error {
			defer close(cleaned)
			close(entered)
			<-release
			return nil
		}, func() (bool, error) { return candidates.Add(1) == 1, nil })
	}()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("handoff returned before canceled child's cleanup")
	case <-time.After(30 * time.Millisecond):
	}
	released.Store(true)
	close(release)
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case <-cleaned:
	default:
		t.Fatal("handoff result preceded child cleanup")
	}
	require.EqualValues(t, 2, candidates.Load())
}

func TestS4USystemContextInspectionDeniesTokensAndCleanupErrors(t *testing.T) {
	for _, scenario := range []string{"normal", "not-system", "process-error", "thread-error", "thread-token", "thread-output-error", "thread-close-error", "cancel-process", "cancel-thread", "cancel-close"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("native identity API failed")
			threadCalls, closeCalls := 0, 0
			err := inspectS4USystemContextFlow(ctx, s4uSystemContextOperations{
				processSystem: func() (bool, error) {
					if scenario == "cancel-process" {
						cancel()
					}
					if scenario == "process-error" {
						return false, failure
					}
					return scenario != "not-system", nil
				},
				threadToken: func() (uintptr, error) {
					threadCalls++
					if scenario == "cancel-thread" {
						cancel()
					}
					if scenario == "thread-error" {
						return 0, failure
					}
					if scenario == "thread-output-error" {
						return 7, failure
					}
					if scenario == "thread-token" || scenario == "thread-close-error" || scenario == "cancel-close" {
						return 7, nil
					}
					return 0, nil
				},
				closeToken: func(handle uintptr) error {
					closeCalls++
					require.Equal(t, uintptr(7), handle)
					if scenario == "cancel-close" {
						cancel()
					}
					if scenario == "thread-close-error" {
						return failure
					}
					return nil
				},
			})
			if scenario == "normal" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if scenario == "not-system" || scenario == "process-error" || scenario == "cancel-process" {
				require.Zero(t, threadCalls)
			} else {
				require.Equal(t, 1, threadCalls)
			}
			if scenario == "thread-token" || scenario == "thread-output-error" || scenario == "thread-close-error" || scenario == "cancel-close" {
				require.Equal(t, 1, closeCalls)
				require.ErrorIs(t, err, errS4USystemContext)
			} else {
				require.Zero(t, closeCalls)
			}
			if scenario == "process-error" || scenario == "thread-error" || scenario == "thread-output-error" || scenario == "thread-close-error" {
				require.ErrorIs(t, err, failure)
			}
			if scenario == "cancel-process" || scenario == "cancel-thread" || scenario == "cancel-close" {
				require.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

func TestS4USystemContextInspectionRequiresLiveContextAndEveryOperation(t *testing.T) {
	called := false
	api := s4uSystemContextOperations{
		processSystem: func() (bool, error) { called = true; return true, nil },
		threadToken:   func() (uintptr, error) { called = true; return 0, nil },
		closeToken:    func(uintptr) error { called = true; return nil },
	}
	require.Error(t, inspectS4USystemContextFlow(nil, api))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, inspectS4USystemContextFlow(ctx, api), context.Canceled)
	for _, incomplete := range []s4uSystemContextOperations{
		{threadToken: api.threadToken, closeToken: api.closeToken},
		{processSystem: api.processSystem, closeToken: api.closeToken},
		{processSystem: api.processSystem, threadToken: api.threadToken},
	} {
		require.Error(t, inspectS4USystemContextFlow(t.Context(), incomplete))
	}
	require.False(t, called)
}
