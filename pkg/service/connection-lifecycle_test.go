package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectionLifecycleDrainsRegisteredConnectionsAndRejectsLateRegistrations(t *testing.T) {
	lifecycle := newConnectionLifecycle()
	release, ok := lifecycle.register()
	require.True(t, ok)
	lifecycle.stop()

	_, ok = lifecycle.register()
	require.False(t, ok)
	done := make(chan bool, 1)
	go func() { done <- lifecycle.wait(time.Second) }()
	select {
	case <-done:
		t.Fatal("connection lifecycle drained before the registered connection was released")
	case <-time.After(25 * time.Millisecond):
	}

	release()
	release()
	select {
	case drained := <-done:
		require.True(t, drained)
	case <-time.After(time.Second):
		t.Fatal("connection lifecycle did not drain")
	}
}

func TestConnectionLifecycleWaitIsBounded(t *testing.T) {
	lifecycle := newConnectionLifecycle()
	_, ok := lifecycle.register()
	require.True(t, ok)

	started := time.Now()
	require.False(t, lifecycle.wait(25*time.Millisecond))
	require.GreaterOrEqual(t, time.Since(started), 20*time.Millisecond)
}

func TestConnectionLifecycleWaitTimeoutStartsWhenWaiting(t *testing.T) {
	lifecycle := newConnectionLifecycle()
	release, ok := lifecycle.register()
	require.True(t, ok)
	lifecycle.stop()
	time.Sleep(25 * time.Millisecond)
	go func() {
		time.Sleep(10 * time.Millisecond)
		release()
	}()

	require.True(t, lifecycle.wait(100*time.Millisecond))
}
