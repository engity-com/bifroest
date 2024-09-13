package net

import (
	"io"
	"net"
	"time"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func NewConnectionFrom(reader io.Reader, writer io.Writer, opts ...ConnectionFromOpt) net.Conn {
	result := &connectionFrom{
		reader:     reader,
		writer:     writer,
		localAddr:  pipeAddrV,
		remoteAddr: pipeAddrV,
	}
	for _, opt := range opts {
		opt(result)
	}
	return result
}

type ConnectionFromOpt func(*connectionFrom)

func ConnectionWithLocalAddr(addr net.Addr) ConnectionFromOpt {
	return func(c *connectionFrom) {
		c.localAddr = addr
	}
}

func ConnectionWithRemoteAddr(addr net.Addr) ConnectionFromOpt {
	return func(c *connectionFrom) {
		c.remoteAddr = addr
	}
}

type connectionFrom struct {
	reader io.Reader
	writer io.Writer

	localAddr  net.Addr
	remoteAddr net.Addr
}

func (this *connectionFrom) LocalAddr() net.Addr {
	return this.localAddr
}

func (this *connectionFrom) RemoteAddr() net.Addr {
	return this.remoteAddr
}

func (this *connectionFrom) Read(b []byte) (int, error) {
	fail := func(err error) (int, error) {
		return 0, &net.OpError{
			Op:   "read",
			Net:  this.RemoteAddr().Network(),
			Addr: this.RemoteAddr(),
			Err:  err,
		}
	}
	n, err := this.reader.Read(b)
	if err != nil {
		return fail(err)
	}
	return n, nil
}

func (this *connectionFrom) Write(b []byte) (int, error) {
	fail := func(err error) (int, error) {
		return 0, &net.OpError{
			Op:   "write",
			Net:  this.RemoteAddr().Network(),
			Addr: this.RemoteAddr(),
			Err:  err,
		}
	}
	n, err := this.writer.Write(b)
	if err != nil {
		return fail(err)
	}
	return n, nil
}

func (this *connectionFrom) SetDeadline(t time.Time) error {
	return errors.Network.Newf("set deadline not supported")
}

func (this *connectionFrom) SetReadDeadline(time.Time) error {
	return errors.Network.Newf("set read deadline not supported")
}

func (this *connectionFrom) SetWriteDeadline(t time.Time) error {
	return errors.Network.Newf("set write deadline not supported")
}

func (this *connectionFrom) Close() (rErr error) {
	defer func() {

	}()
	if c, ok := this.reader.(io.Closer); ok {
		defer common.KeepCloseError(&rErr, c)
	}
	if c, ok := this.writer.(io.Closer); ok {
		defer common.KeepCloseError(&rErr, c)
	}
	return nil
}

var pipeAddrV = pipeAddr{}

type pipeAddr struct{}

func (pipeAddr) Network() string     { return "pipe" }
func (this pipeAddr) String() string { return this.Network() }
