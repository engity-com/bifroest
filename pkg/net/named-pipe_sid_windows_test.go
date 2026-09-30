//go:build windows

package net

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestNamedPipeForSidAllowsTargetUser(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	pipe, err := NewNamedPipeForSid("ssh-agent", user.User.Sid.String())
	require.NoError(t, err)
	defer pipe.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan error, 1)
	go func() {
		conn, err := pipe.AcceptConn()
		if err == nil {
			err = conn.Close()
		}
		accepted <- err
	}()
	conn, err := ConnectToNamedPipe(ctx, pipe.Path())
	require.NoError(t, err)
	defer conn.Close()
	select {
	case err := <-accepted:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("timed out accepting the target user's named pipe connection")
	}
}
