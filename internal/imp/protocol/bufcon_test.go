package protocol

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestBufConn(t *testing.T) {
	givenConn := newTestConnectionOf("0123456789")
	instance := NewBufConn(givenConn).(*bufConn)
	defer instance.Release()

	{
		actual, actualErr := instance.Peek(-3)
		require.Equal(t, bufio.ErrNegativeCount, actualErr)
		require.Equal(t, []byte(nil), actual)
	}
	{
		actual, actualErr := instance.Peek(bufConnSize + 1)
		require.Equal(t, bufio.ErrBufferFull, actualErr)
		require.Equal(t, []byte(nil), actual)
	}
	{
		actual, actualErr := instance.Peek(0)
		require.NoError(t, actualErr)
		require.Equal(t, []byte(nil), actual)
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 0, instance.bufLen)
	}
	{
		actual, actualErr := instance.Peek(3)
		require.NoError(t, actualErr)
		require.Equal(t, "012", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 3, instance.bufLen)
	}
	{
		actual, actualErr := instance.Peek(4)
		require.NoError(t, actualErr)
		require.Equal(t, "0123", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual, actualErr := instance.Peek(2)
		require.NoError(t, actualErr)
		require.Equal(t, "01", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual := make([]byte, 3)
		actualN, actualErr := instance.Read(actual)
		require.NoError(t, actualErr)
		require.Equal(t, 3, actualN)
		require.Equal(t, "012", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 3, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual := make([]byte, 4)
		actualN, actualErr := instance.Read(actual)
		require.NoError(t, actualErr)
		require.Equal(t, 4, actualN)
		require.Equal(t, "3456", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 4, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual, actualErr := instance.Peek(2)
		require.ErrorContains(t, actualErr, "there was already regular read activity on this connection; Peek(..) is not longer possible")
		require.Equal(t, []byte(nil), actual)
	}
	{
		actual := make([]byte, 2)
		actualN, actualErr := instance.Read(actual)
		require.NoError(t, actualErr)
		require.Equal(t, 2, actualN)
		require.Equal(t, "78", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 4, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual := make([]byte, 4)
		actualN, actualErr := instance.Read(actual)
		require.NoError(t, actualErr)
		require.Equal(t, 1, actualN)
		require.Equal(t, "9", string(actual[:actualN]))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 4, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actualErr := instance.Close()
		require.NoError(t, actualErr)
		assert.Equal(t, true, instance.closed.Load())
		assert.Equal(t, 4, instance.bufPos)
		assert.Equal(t, 4, instance.bufLen)
	}
	{
		actual := make([]byte, 4)
		actualN, actualErr := instance.Read(actual)
		require.Equal(t, io.ErrClosedPipe, actualErr)
		require.Equal(t, 0, actualN)
	}
	{
		actual, actualErr := instance.Peek(4)
		require.Equal(t, io.ErrClosedPipe, actualErr)
		require.Equal(t, []byte(nil), actual)
	}
	{
		instance.Release()
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 0, instance.bufLen)
	}
}

func TestBufConn_2(t *testing.T) {
	givenConn := newTestConnectionOf("0123456789")
	instance := NewBufConn(givenConn).(*bufConn)
	defer common.IgnoreCloseError(instance)

	{
		actual, actualErr := instance.Peek(3)
		require.NoError(t, actualErr)
		require.Equal(t, "012", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 0, instance.bufPos)
		assert.Equal(t, 3, instance.bufLen)
	}
	{
		actual := make([]byte, 5)
		actualN, actualErr := instance.Read(actual)
		require.NoError(t, actualErr)
		require.Equal(t, 5, actualN)
		require.Equal(t, "01234", string(actual))
		assert.Equal(t, false, instance.closed.Load())
		assert.Equal(t, 3, instance.bufPos)
		assert.Equal(t, 3, instance.bufLen)
	}
}

func newTestConnectionOf(what string) *testConn {
	return &testConn{
		Reader: strings.NewReader(what),
	}
}

type testConn struct {
	io.Reader
	closed atomic.Bool
}

func (this *testConn) Write([]byte) (int, error) {
	panic("not implemented")
}

func (this *testConn) Close() error {
	if this.closed.CompareAndSwap(false, true) {
		return nil
	}
	return io.ErrClosedPipe
}

func (this *testConn) LocalAddr() net.Addr {
	panic("not implemented")
}

func (this *testConn) RemoteAddr() net.Addr {
	panic("not implemented")
}

func (this *testConn) SetDeadline(time.Time) error {
	panic("not implemented")
}

func (this *testConn) SetReadDeadline(time.Time) error {
	panic("not implemented")
}

func (this *testConn) SetWriteDeadline(time.Time) error {
	panic("not implemented")
}
