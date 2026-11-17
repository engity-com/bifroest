package environment

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/engity-com/bifroest/pkg/terminal"
)

func TestTerminalQueueSizeReturnsInitialSizeBeforeChanges(t *testing.T) {
	changes := make(chan terminal.Window, 1)
	changes <- terminal.Window{Width: 101, Height: 47}
	close(changes)
	queue := terminalQueueSize{
		ctx:     t.Context(),
		initial: &remotecommand.TerminalSize{Width: 77, Height: 33},
		changes: changes,
	}

	require.Equal(t, &remotecommand.TerminalSize{Width: 77, Height: 33}, queue.Next())
	require.Equal(t, &remotecommand.TerminalSize{Width: 101, Height: 47}, queue.Next())
	require.Nil(t, queue.Next())
}

func TestTerminalQueueSizeStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	queue := terminalQueueSize{ctx: ctx, changes: make(chan terminal.Window)}
	require.Nil(t, queue.Next())
}
