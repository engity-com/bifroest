package managementclient

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func checkStalledAgentIsClosedOnCancel(t *testing.T, listener net.Listener, address string) {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			acceptErr <- err
		} else {
			accepted <- peer
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	client, closer, err := connectAgent(ctx, address)
	require.NoError(t, err)
	defer func() { require.NoError(t, closer.Close()) }()
	var peer net.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case err := <-acceptErr:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not accept the connection")
	}
	finished := make(chan error, 1)
	go func() {
		_, err := client.Signers()
		finished <- err
	}()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = io.ReadFull(peer, make([]byte, 4)) // The agent request arrived; do not respond.
	require.NoError(t, err)
	cancel()
	select {
	case err := <-finished:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("canceling the command did not interrupt the agent request")
	}
}
