package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/environment"
)

func TestWebTerminalInputByteBudgetFifoWrapAndEof(t *testing.T) {
	input := newWebTerminalInputBuffer()
	first := bytes.Repeat([]byte{'a'}, webTerminalInputBytes)
	require.True(t, input.append(first))
	require.False(t, input.append([]byte{'!'}), "a full 64-KiB buffer cannot accept another byte")
	chunk := make([]byte, webTerminalInputBytes/2)
	n, err := input.read(t.Context(), chunk)
	require.NoError(t, err)
	require.Equal(t, len(chunk), n)
	require.Equal(t, first[:n], chunk)
	second := bytes.Repeat([]byte{'b'}, n)
	require.True(t, input.append(second))
	require.False(t, input.append([]byte{'!'}))
	input.end()
	require.False(t, input.append([]byte{'!'}), "stdin cannot reopen after EOF")
	var output bytes.Buffer
	for {
		n, err := input.read(t.Context(), chunk)
		_, _ = output.Write(chunk[:n])
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.Equal(t, append(first[len(chunk):], second...), output.Bytes())
}

func TestWebTerminalInputCancellationUnblocksReadAndDoesNotDeliverQueuedData(t *testing.T) {
	input := newWebTerminalInputBuffer()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := input.read(ctx, make([]byte, 16)); done <- err }()
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("input cancellation did not unblock")
	}
	require.True(t, input.append([]byte("retained")))
	n, err := input.read(ctx, make([]byte, 16))
	require.Zero(t, n)
	require.ErrorIs(t, err, context.Canceled)
	input.end()
}

type terminalInputCheckedContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (this *terminalInputCheckedContext) Err() error {
	err := this.Context.Err()
	this.once.Do(func() { close(this.checked) })
	return err
}

func TestWebTerminalInputRechecksCancellationAfterWaitingForBufferLock(t *testing.T) {
	input := newWebTerminalInputBuffer()
	require.True(t, input.append([]byte("must-not-be-delivered")))
	base, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &terminalInputCheckedContext{Context: base, checked: make(chan struct{})}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	input.mutex.Lock()
	go func() { n, err := input.read(ctx, make([]byte, 32)); done <- result{n, err} }()
	<-ctx.checked // The first cancellation check happened before cancel.
	cancel()
	input.mutex.Unlock()
	select {
	case got := <-done:
		require.Zero(t, got.n)
		require.ErrorIs(t, got.err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("input reader did not stop after cancellation")
	}
	data := make([]byte, 32)
	n, err := input.read(t.Context(), data)
	require.NoError(t, err)
	require.Equal(t, "must-not-be-delivered", string(data[:n]), "canceled reads must not consume queued input")
}

func TestWebTerminalInputConcurrentProducerAndReaderPreserveBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	input := newWebTerminalInputBuffer()
	want := make([]byte, 8*webTerminalInputBytes)
	for index := range want {
		want[index] = byte(index*37 + index/251)
	}
	filled := make(chan struct{})
	markFilled := sync.OnceFunc(func() { close(filled) })
	consumed := make(chan struct{}, 1)
	written := make(chan error, 1)
	go func() {
		for offset := 0; offset < len(want); {
			n := min(997, len(want)-offset)
			if input.append(want[offset : offset+n]) {
				offset += n
				continue
			}
			markFilled()
			select {
			case <-ctx.Done():
				written <- ctx.Err()
				return
			case <-consumed:
			}
		}
		input.end()
		written <- nil
	}()
	select {
	case <-filled: // The reader deliberately starts only after the bounded buffer fills.
	case <-ctx.Done():
		t.Fatal("producer did not reach the byte bound")
	}
	var got bytes.Buffer
	data := make([]byte, 317)
	for {
		n, err := input.read(ctx, data)
		_, _ = got.Write(data[:n])
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		select {
		case consumed <- struct{}{}:
		default:
		}
	}
	require.NoError(t, <-written)
	require.Equal(t, want, got.Bytes())
}

func FuzzWebTerminalInputBufferMatchesByteStream(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add(bytes.Repeat([]byte{0, 0, 1, 3, 2, 4}, 1024))
	f.Add(bytes.Repeat([]byte{255, 0, 127, 1}, 4096))
	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 32<<10 {
			operations = operations[:32<<10]
		}
		input := newWebTerminalInputBuffer()
		var want []byte
		for index, operation := range operations {
			if operation&1 == 0 {
				data := bytes.Repeat([]byte{byte(index)}, 1+int(operation)*17)
				accepted := len(data) <= webTerminalInputBytes-len(want)
				require.Equal(t, accepted, input.append(data))
				if accepted {
					want = append(want, data...)
				}
			} else if len(want) > 0 {
				data := make([]byte, 1+int(operation)*11)
				n, err := input.read(t.Context(), data)
				require.NoError(t, err)
				require.Equal(t, min(len(data), len(want)), n)
				require.Equal(t, want[:n], data[:n])
				want = want[n:]
			}
		}
		input.end()
		var got bytes.Buffer
		data := make([]byte, 317)
		for {
			n, err := input.read(t.Context(), data)
			_, _ = got.Write(data[:n])
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}
		require.True(t, bytes.Equal(want, got.Bytes()), "buffer differs from the reference byte stream")
	})
}

func TestWebSocketTinyInputFramesSurviveDelayedExecutionStartup(t *testing.T) {
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	fixture := newWebSocketFixture(t, func(task environment.TerminalTask) (int, error) {
		select {
		case <-gate:
		case <-task.Context().Done():
			return -1, task.Context().Err()
		}
		raw, err := io.ReadAll(task.Terminal())
		if err != nil {
			return -1, err
		}
		_, err = task.Terminal().Write(raw)
		return 7, err
	})
	conn := fixture.dial(t)
	require.NoError(t, conn.WriteJSON(webSocketOpen(fixture.login(t))))
	requireWebSocketReady(t, conn)
	pong := make(chan struct{})
	once := sync.Once{}
	conn.SetPongHandler(func(value string) error {
		if value == "queued-input-barrier" {
			once.Do(func() { close(pong) })
		}
		return nil
	})
	type received struct {
		kind int
		data []byte
		err  error
	}
	messages := make(chan received, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			kind, data, err := conn.ReadMessage()
			messages <- received{kind, data, err}
			if err != nil {
				return
			}
		}
	}()
	defer func() { _ = conn.Close(); <-done }()
	want := []byte("tiny-input-before-native-start")
	for _, value := range want {
		require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte{value}))
	}
	require.NoError(t, conn.WriteControl(websocket.PingMessage, []byte("queued-input-barrier"), time.Now().Add(time.Second)))
	select {
	case <-pong:
	case got := <-messages:
		t.Fatalf("input was rejected before the delayed backend read: %v", got.err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not process the queued input barrier")
	}
	require.NoError(t, conn.WriteJSON(map[string]string{"type": "eof"}))
	release()
	var output bytes.Buffer
	for {
		select {
		case got := <-messages:
			require.NoError(t, got.err)
			if got.kind == websocket.BinaryMessage {
				require.Greater(t, len(got.data), 1)
				_, _ = output.Write(got.data[1:])
				continue
			}
			var status struct {
				Type   string `json:"type"`
				Status uint32 `json:"status"`
			}
			require.NoError(t, json.Unmarshal(got.data, &status))
			require.Equal(t, "exit", status.Type)
			require.EqualValues(t, 7, status.Status)
			require.Equal(t, want, output.Bytes())
			return
		case <-time.After(2 * time.Second):
			t.Fatal("delayed input did not drain")
		}
	}
}
