package net

import (
	gonet "net"
)

func AsListener[C gonet.Conn](
	accept func() (C, error),
	close func() error,
	addr func() string,
) (gonet.Listener, error) {
	return &listener[C]{accept, close, addr}, nil
}

type listener[C gonet.Conn] struct {
	accept func() (C, error)
	close  func() error
	addr   func() string
}

func (this *listener[C]) Accept() (gonet.Conn, error) {
	result, err := this.accept()
	return result, err
}

func (this *listener[C]) Close() error {
	return this.close()
}

func (this *listener[C]) Addr() gonet.Addr {
	return addrAdapter(this.addr)
}

type addrAdapter func() string

func (this addrAdapter) Network() string {
	return this()
}

func (this addrAdapter) String() string {
	return this()
}
