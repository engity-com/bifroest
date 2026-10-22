package environment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/engity-com/bifroest/pkg/terminal"
)

func TestNeutralTerminalQueueReturnsInitialAndChangesThenStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	changes := make(chan terminal.Window, 1)
	changes <- terminal.Window{Width: 100, Height: 40}
	queue := terminalQueueSize{ctx: ctx, initial: &remotecommand.TerminalSize{Width: 80, Height: 24}, changes: changes}
	require.Equal(t, &remotecommand.TerminalSize{Width: 80, Height: 24}, queue.Next())
	require.Equal(t, &remotecommand.TerminalSize{Width: 100, Height: 40}, queue.Next())
	completed := make(chan *remotecommand.TerminalSize, 1)
	go func() { completed <- queue.Next() }()
	cancel()
	select {
	case value := <-completed:
		require.Nil(t, value)
	case <-time.After(time.Second):
		t.Fatal("idle resize source prevented cancellation")
	}
}
