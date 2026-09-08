package protocol

import (
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestServeConnCancelsHandlerWhenClientDisconnects(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	client, err := gonet.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	server, err := listener.Accept()
	require.NoError(t, err)

	serveDone := make(chan error, 1)
	instance := &imp{Imp: &Imp{ExitCodeByConnectionIdPath: t.TempDir()}}
	go func() { serveDone <- instance.serveConn(context.Background(), server) }()
	clientConn := codec.NewMsgPackConn(client)
	executionId, err := execution.NewId()
	require.NoError(t, err)
	require.NoError(t, (Header{Method: MethodKillExecution, ConnectionId: connection.MustNewId()}).EncodeMsgPack(clientConn))
	require.NoError(t, (methodKillExecutionRequest{executionId: executionId, signal: sys.SIGKILL}).EncodeMsgPack(clientConn))
	require.NoError(t, client.Close())

	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("handler was not canceled after the client disconnected")
	}
}
