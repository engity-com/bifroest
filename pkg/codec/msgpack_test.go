package codec

import (
	"io"
	gonet "net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMsgPackConnDelegatesCloseWriteWithoutClosingReadSide(t *testing.T) {
	client, server := gonet.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	t.Cleanup(func() { _ = server.Close() })
	underlying := &trackingCloseWriterConn{Conn: client}
	conn := NewMsgPackConn(underlying)
	closeWriter, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok)
	require.NoError(t, closeWriter.CloseWrite())
	require.True(t, underlying.closeWriteCalled.Load())

	writeDone := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("response after half-close"))
		writeDone <- err
	}()
	response := make([]byte, len("response after half-close"))
	_, err := io.ReadFull(conn, response)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)
	require.Equal(t, "response after half-close", string(response))
}

type trackingCloseWriterConn struct {
	gonet.Conn
	closeWriteCalled atomic.Bool
}

func (this *trackingCloseWriterConn) CloseWrite() error {
	this.closeWriteCalled.Store(true)
	return nil
}
