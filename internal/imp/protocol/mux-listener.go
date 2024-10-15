package protocol

import (
	"fmt"
	"io"
	gonet "net"
	"sync/atomic"

	log "github.com/echocat/slf4g"
	"github.com/things-go/go-socks5/statute"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
)

func NewMuxListener(of gonet.Listener) MuxListener {
	result := &muxListener{
		Listener: of,
	}
	result.rpc.muxListener = result
	result.rpc.connChan = make(chan gonet.Conn, 1)
	result.rpc.errChan = make(chan error, 1)
	result.socks5.muxListener = result
	result.socks5.connChan = make(chan gonet.Conn, 1)
	result.socks5.errChan = make(chan error, 1)
	go result.run()
	return result
}

type MuxListener interface {
	io.Closer
	Rpc() gonet.Listener
	Socks5() gonet.Listener
}

type muxListener struct {
	gonet.Listener

	rpc    muxListenerChild
	socks5 muxListenerChild
}

func (this *muxListener) run() struct{} {
	fail := func(err error) struct{} {
		this.rpc.sendErr(err)
		this.socks5.sendErr(err)
		return struct{}{}
	}
	for {
		conn, err := this.Accept()
		if net.IsClosedError(err) {
			this.closeChans()
			return struct{}{}
		}
		if err != nil {
			return fail(err)
		}

		if err := this.handleNewConn(conn); err != nil {
			return fail(err)
		}
	}
}

func (this *muxListener) handleNewConn(conn gonet.Conn) error {
	success := false
	defer common.IgnoreCloseErrorIfFalse(&success, conn)

	bc := NewBufConn(conn)
	peek, err := bc.Peek(1)
	if net.IsClosedError(err) {
		return nil
	}
	if err != nil {
		return err
	}
	log.Withf("peek", "%d", peek[0]).
		Withf("socks5", "%d", statute.VersionSocks5).
		Withf("rpc", "%d", HeaderMagic).
		With("remote", conn.RemoteAddr()).
		Info("new connection")
	switch peek[0] {
	case statute.VersionSocks5:
		this.socks5.connChan <- bc
	case HeaderMagic:
		this.rpc.connChan <- bc
	default:
		return fmt.Errorf("invalid magic; got %d (supported is socks5=%d, rpc=%d)", peek[0], statute.VersionSocks5, HeaderMagic)
	}
	success = true
	return nil
}

func (this *muxListener) Rpc() gonet.Listener {
	return &this.rpc
}

func (this *muxListener) Socks5() gonet.Listener {
	return &this.socks5
}

func (this *muxListener) Close() error {
	defer this.closeChans()
	return this.Listener.Close()
}

func (this *muxListener) closeChans() {
	defer this.rpc.close()
	defer this.socks5.close()
}

type muxListenerChild struct {
	*muxListener
	connChan       chan gonet.Conn
	connChanClosed atomic.Bool
	errChan        chan error
	errChanClosed  atomic.Bool
}

func (this *muxListenerChild) sendErr(err error) {
	if this.errChanClosed.Load() {
		return
	}
	defer func() {
		if e := recover(); e != nil && e != "send on closed channel" {
			panic(e)
		}
	}()
	this.errChan <- err
}

func (this *muxListenerChild) Accept() (gonet.Conn, error) {
	select {
	case result, ok := <-this.connChan:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return result, nil
	case err, ok := <-this.errChan:
		if !ok {
			return nil, io.ErrClosedPipe
		}
		return nil, err
	}
}

func (this *muxListenerChild) close() {
	defer func() {
		if this.connChanClosed.CompareAndSwap(false, true) {
			close(this.connChan)
		}
	}()
	defer func() {
		if this.errChanClosed.CompareAndSwap(false, true) {
			close(this.errChan)
		}
	}()
}
