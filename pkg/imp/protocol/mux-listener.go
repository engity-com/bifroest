package protocol

import (
	"fmt"
	"io"
	gonet "net"

	"github.com/things-go/go-socks5/statute"

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
		this.rpc.errChan <- err
		this.socks5.errChan <- err
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

		bc := NewBufConn(conn)
		peek, err := bc.Peek(1)
		if err != nil {
			return fail(err)
		}
		switch peek[0] {
		case statute.VersionSocks5:
			this.socks5.connChan <- bc
		case HeaderMagic:
			this.rpc.connChan <- bc
		default:
			return fail(fmt.Errorf("invalid magic; got %d (supported is socks5=%d, rpc=%d)", peek[0], statute.VersionSocks5, HeaderMagic))
		}
	}
}

func (this *muxListener) Rpc() gonet.Listener {
	return this.rpc.muxListener
}

func (this *muxListener) Socks5() gonet.Listener {
	return this.socks5.muxListener
}

func (this *muxListener) Close() error {
	defer this.closeChans()
	return this.Listener.Close()
}

func (this *muxListener) closeChans() {
	defer close(this.rpc.connChan)
	defer close(this.rpc.errChan)
	defer close(this.socks5.connChan)
	defer close(this.socks5.errChan)
}

type muxListenerChild struct {
	*muxListener
	connChan chan gonet.Conn
	errChan  chan error
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
