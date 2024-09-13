package sys

import (
	"fmt"
	"io"
	gonet "net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

func NewStdinStdoutSocket(signalImmediately bool, opts ...FileListenerOpt) gonet.Listener {
	opts = append([]FileListenerOpt{FileListenerWithAddr(stdinStdoutAddrV)}, opts...)
	result, ch := NewFileSocket(os.Stdin, os.Stdout, opts...)

	sc := make(chan os.Signal, 1)
	go func() {
		if signalImmediately {
			ch <- struct{}{}
		}
		signal.Notify(sc, os.Interrupt)
		for {
			_, ok := <-sc
			if !ok {
				return
			}
			ch <- struct{}{}
		}

	}()
	result.(*fileSocket).onBeforeClose = func() {
		select {
		case <-sc:
			// ignore
		default:
			defer func() {
				_ = recover()
			}()
			close(sc)
		}
	}
	return result
}

type ReadableFile interface {
	io.ReadCloser
	CloneableFile
}

type WriteableFile interface {
	io.WriteCloser
	CloneableFile
}

func NewFileSocket(reader ReadableFile, writer WriteableFile, opts ...FileListenerOpt) (gonet.Listener, chan struct{}) {
	result := &fileSocket{
		reader:        reader,
		writer:        writer,
		trigger:       make(chan struct{}),
		localDone:     make(chan struct{}),
		onBeforeClose: func() {},
	}
	result.addr = &fileSocketAddr{result}
	result.onBeforeClose = result.noopOnBeforeClose
	for _, opt := range opts {
		opt(result)
	}
	return result, result.trigger
}

type FileListenerOpt func(*fileSocket)

func FileListenerWithAddr(addr gonet.Addr) FileListenerOpt {
	return func(c *fileSocket) {
		c.addr = addr
	}
}

type fileSocket struct {
	reader ReadableFile
	writer WriteableFile
	addr   gonet.Addr

	trigger       chan struct{}
	onBeforeClose func()

	activeConn atomic.Pointer[fileSocketConn]

	once      sync.Once // Protects closing localDone
	localDone chan struct{}
}

func (this *fileSocket) noopOnBeforeClose() {}

func (this *fileSocket) Accept() (gonet.Conn, error) {
	fail := func(err error) (gonet.Conn, error) {
		return nil, &gonet.OpError{
			Op:   "accept",
			Net:  this.Addr().Network(),
			Addr: this.Addr(),
			Err:  err,
		}
	}

	select {
	case <-this.localDone:
		return fail(io.ErrClosedPipe)
	case _, ok := <-this.trigger:
		if !ok {
			return fail(io.ErrClosedPipe)
		}
		break
	}

	for {
		current := this.activeConn.Load()
		if current == nil {
			break
		}
		// Prevent that we have several connections on the same file.
		// This does not work, therefore close the other connection.
		_ = current.Close()
		if this.activeConn.CompareAndSwap(current, nil) {
			break
		}
	}

	success := false
	reader, err := CloneFile(this.reader)
	if err != nil {
		return fail(err)
	}
	defer common.DoOnFailureIgnore(&success, reader.Close)
	writer, err := CloneFile(this.writer)
	if err != nil {
		return fail(err)
	}
	defer common.DoOnFailureIgnore(&success, writer.Close)

	newConn := net.NewConnectionFrom(
		reader,
		writer,
		net.ConnectionWithRemoteAddr(this.Addr()),
		net.ConnectionWithLocalAddr(this.Addr()),
	)
	result := &fileSocketConn{this, newConn}
	success = true
	return result, nil
}

func (this *fileSocket) Close() (rErr error) {
	this.once.Do(func() { close(this.localDone) })
	defer func() {
		defer func() {
			_ = recover()
		}()
		close(this.trigger)
	}()
	defer common.KeepCloseError(&rErr, this.writer)
	defer common.KeepCloseError(&rErr, this.reader)
	defer this.onBeforeClose()
	return nil
}

func (this *fileSocket) Addr() gonet.Addr {
	return this.addr
}

func (this *fileSocket) String() string {
	return this.Addr().String()
}

type fileSocketAddr struct {
	*fileSocket
}

func (*fileSocketAddr) Network() string { return "file" }
func (this *fileSocketAddr) String() string {
	return fmt.Sprintf("file:%s>%s", this.reader.Name(), this.writer.Name())
}

var stdinStdoutAddrV = stdinStdoutAddr{}

type stdinStdoutAddr struct{}

func (stdinStdoutAddr) Network() string     { return "stdinstdout" }
func (this stdinStdoutAddr) String() string { return this.Network() }

type fileSocketConn struct {
	parent *fileSocket
	gonet.Conn
}

func (this *fileSocketConn) Close() error {
	this.parent.activeConn.CompareAndSwap(this, nil)
	return this.Conn.Close()
}
