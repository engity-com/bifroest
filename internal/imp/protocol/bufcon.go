package protocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const (
	bufConnSize = 4096
)

var bufConnPool = sync.Pool{
	New: func() any {
		return &bufConn{
			buf: make([]byte, bufConnSize),
		}
	},
}

func NewBufConn(in net.Conn) BufConn {
	result := bufConnPool.Get().(*bufConn)
	result.Conn = in
	return result
}

type bufConn struct {
	net.Conn

	buf    []byte
	bufLen int
	bufPos int
	closed atomic.Bool
}

func (this *bufConn) Read(p []byte) (n int, err error) {
	if this.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	leftInBuf := this.bufLen - this.bufPos
	if leftInBuf <= 0 {
		return this.Conn.Read(p)
	}

	pLen := len(p)
	if pLen <= leftInBuf {
		copy(p, this.buf[this.bufPos:this.bufPos+pLen])
		this.bufPos += pLen
		return pLen, nil
	}

	copy(p, this.buf[this.bufPos:this.bufPos+leftInBuf])
	n += leftInBuf
	this.bufPos += leftInBuf

	nr, err := this.Conn.Read(p[leftInBuf:])
	n += nr

	return n, err
}

func (this *bufConn) Peek(n int) ([]byte, error) {
	if this.closed.Load() {
		return nil, io.ErrClosedPipe
	}
	if this.bufPos > 0 {
		return nil, fmt.Errorf("there was already regular read activity on this connection; Peek(..) is not longer possible")
	}
	if n < 0 {
		return nil, bufio.ErrNegativeCount
	}
	if n == 0 {
		return nil, nil
	}
	if n > len(this.buf) {
		return nil, bufio.ErrBufferFull
	}

	if this.bufLen < n {
		nr, err := this.Conn.Read(this.buf[this.bufLen:n])
		if err != nil {
			return this.buf[:this.bufLen+nr], err
		}
		if n-this.bufLen > nr {
			return this.buf[:this.bufLen+nr], io.EOF
		}
		this.bufLen += nr
	}

	return this.buf[:n], nil
}

func (this *bufConn) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	return this.Conn.Close()
}

func (this *bufConn) Release() {
	this.Conn = nil
	this.bufLen = 0
	this.bufPos = 0
	this.closed.Store(false)
	bufConnPool.Put(this)
}

type BufConn interface {
	net.Conn

	Release()
	Peek(int) ([]byte, error)
}
