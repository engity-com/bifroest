package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/stretchr/testify/require"
)

type testResponse struct {
	input                  io.Reader
	read                   func([]byte) (int, error)
	complete, abort, close func() error
	mutex                  sync.Mutex
	events                 []string
}

func (this *testResponse) note(event string) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.events = append(this.events, event)
}
func (this *testResponse) snapshot() []string {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return append([]string(nil), this.events...)
}
func (this *testResponse) Read(p []byte) (int, error) {
	if this.read != nil {
		return this.read(p)
	}
	return this.input.Read(p)
}
func (this *testResponse) Complete() error {
	this.note("complete")
	if this.complete != nil {
		return this.complete()
	}
	return nil
}
func (this *testResponse) Abort() error {
	this.note("abort")
	if this.abort != nil {
		return this.abort()
	}
	return nil
}
func (this *testResponse) Close() error {
	this.note("close")
	if this.close != nil {
		return this.close()
	}
	return nil
}

type received[T any] struct {
	value T
	err   error
}

func await[T any](t *testing.T, results <-chan received[T]) received[T] {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("response owner did not finish")
		return received[T]{}
	}
}
func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("response phase was not reached")
	}
}

func TestReceiveWaitsForFinalTransportSuccessBeforeReturningTypedData(t *testing.T) {
	encoded, err := wire.EncodeWireResult([]string{"decoded-but-provisional"})
	require.NoError(t, err)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	response := &testResponse{input: bytes.NewReader(encoded), complete: func() error { close(started); <-release; return nil }, abort: func() error { unblock(); return nil }}
	finished := make(chan received[[]string], 1)
	go func() {
		value, err := ReadWireResult[[]string](t.Context(), response)
		finished <- received[[]string]{value, err}
	}()
	awaitSignal(t, started)
	select {
	case <-finished:
		t.Fatal("decoded bytes were returned before transport completion")
	default:
	}
	unblock()
	result := await(t, finished)
	require.NoError(t, result.err)
	require.Equal(t, []string{"decoded-but-provisional"}, result.value)
	require.Equal(t, []string{"complete", "close"}, response.snapshot())
}

func TestReceiveReturnsZeroAndRetainsEveryFailureWithoutRetry(t *testing.T) {
	decodeErr, completeErr, abortErr, closeErr := errors.New("decode failed"), errors.New("remote final audit failed"), errors.New("abort failed"), errors.New("close failed")
	for _, test := range []struct {
		name                           string
		decode, complete, abort, close error
		events                         []string
	}{
		{"decode", decodeErr, nil, nil, nil, []string{"abort", "complete", "close"}},
		{"completion", nil, completeErr, nil, nil, []string{"complete", "abort", "close"}},
		{"cleanup", nil, nil, nil, closeErr, []string{"complete", "close"}},
		{"all", decodeErr, completeErr, abortErr, closeErr, []string{"abort", "complete", "close"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := &testResponse{complete: func() error { return test.complete }, abort: func() error { return test.abort }, close: func() error { return test.close }}
			value, err := Receive(t.Context(), response, func(io.Reader) (map[string]string, error) {
				return map[string]string{"private": "provisional"}, test.decode
			})
			require.Error(t, err)
			require.Nil(t, value)
			for _, cause := range []error{test.decode, test.complete, test.abort, test.close} {
				if cause != nil {
					require.ErrorIs(t, err, cause)
				}
			}
			require.Equal(t, test.events, response.snapshot())
		})
	}
}

func TestReceiveCancelledBeforeDecodeStillAbortsJoinsAndCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	response := &testResponse{}
	value, err := Receive(ctx, response, func(io.Reader) (string, error) { t.Fatal("canceled response must not invoke decoder"); return "", nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, value)
	require.Equal(t, []string{"abort", "complete", "close"}, response.snapshot())
}

func TestReceiveCancellationUnblocksBothReadAndComplete(t *testing.T) {
	for _, phase := range []string{"read", "complete"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			started, aborted := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(aborted) }) }
			t.Cleanup(unblock)
			response := &testResponse{input: bytes.NewReader([]byte("provisional")), abort: func() error { unblock(); return nil }}
			if phase == "read" {
				response.read = func([]byte) (int, error) { close(started); <-aborted; return 0, io.ErrClosedPipe }
			} else {
				response.complete = func() error { close(started); <-aborted; return nil }
			}
			finished := make(chan received[[]byte], 1)
			go func() { value, err := ReadBytes(ctx, response, 4096); finished <- received[[]byte]{value, err} }()
			awaitSignal(t, started)
			cancel()
			result := await(t, finished)
			require.ErrorIs(t, result.err, context.Canceled)
			require.Nil(t, result.value)
			events := response.snapshot()
			require.Len(t, events, 3)
			require.Equal(t, "close", events[2])
			require.Contains(t, events, "abort")
			require.Contains(t, events, "complete")
		})
	}
}

func TestReceiveJoinsCancellationCallbackBeforeClosingOrReturning(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	abortStarted, releaseAbort := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(releaseAbort) }) }
	t.Cleanup(unblock)
	response := &testResponse{input: bytes.NewReader([]byte("provisional")), complete: func() error { cancel(); <-abortStarted; return nil }, abort: func() error { close(abortStarted); <-releaseAbort; return nil }}
	finished := make(chan received[[]byte], 1)
	go func() { value, err := ReadBytes(ctx, response, 4096); finished <- received[[]byte]{value, err} }()
	awaitSignal(t, abortStarted)
	select {
	case <-finished:
		t.Fatal("cancellation callback outlived Receive")
	default:
	}
	require.NotContains(t, response.snapshot(), "close")
	unblock()
	result := await(t, finished)
	require.ErrorIs(t, result.err, context.Canceled)
	require.Nil(t, result.value)
	require.Equal(t, []string{"complete", "abort", "close"}, response.snapshot())
}

func TestReceiveLateCancellationDuringLocalCloseCannotBecomeSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	response := &testResponse{input: bytes.NewReader([]byte("provisional")), close: func() error { cancel(); return nil }}
	value, err := ReadBytes(ctx, response, 4096)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, value)
	require.Equal(t, []string{"complete", "close"}, response.snapshot())
}

func TestReceiveOwnsCleanupForNilDecoderAndCallerPanic(t *testing.T) {
	response := &testResponse{}
	value, err := Receive[string](nil, response, nil)
	require.Error(t, err)
	require.Empty(t, value)
	require.Equal(t, []string{"abort", "complete", "close"}, response.snapshot())
	response = &testResponse{}
	require.Panics(t, func() {
		_, _ = Receive(t.Context(), response, func(io.Reader) (string, error) { panic("caller decoder panicked") })
	})
	require.Equal(t, []string{"abort", "complete", "close"}, response.snapshot())
	_, err = Receive[string](t.Context(), nil, func(io.Reader) (string, error) { return "", nil })
	require.Error(t, err)
}

func TestReceiveDoesNotRetryPanickingCompletion(t *testing.T) {
	response := &testResponse{complete: func() error { panic("adapter completion panicked") }}
	require.Panics(t, func() {
		_, _ = Receive(t.Context(), response, func(io.Reader) (string, error) { return "provisional", nil })
	})
	require.Equal(t, []string{"complete", "abort", "close"}, response.snapshot())
}
