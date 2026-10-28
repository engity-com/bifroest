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
