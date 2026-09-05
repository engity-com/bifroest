//go:build !windows

package environment

import (
	"testing"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/remotecommand"
)

func TestTerminalQueueSizeFromSshReturnsInitialSizeBeforeChanges(t *testing.T) {
	changes := make(chan essh.Window, 1)
	changes <- essh.Window{Width: 101, Height: 47}
	close(changes)
	queue := terminalQueueSizeFromSsh{
		initial: &remotecommand.TerminalSize{Width: 77, Height: 33},
		changes: changes,
	}

	require.Equal(t, &remotecommand.TerminalSize{Width: 77, Height: 33}, queue.Next())
	require.Equal(t, &remotecommand.TerminalSize{Width: 101, Height: 47}, queue.Next())
	require.Nil(t, queue.Next())
}
