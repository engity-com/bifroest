package net

import (
	"net"
)

func AsListener[C net.Conn](
	accept func() (C, error),
	close func() error,
	addr func() string,
) (net.Listener, error) {
	return &listener[C]{accept, close, addr}, nil
}

type listener[C net.Conn] struct {
	accept func() (C, error)
	close  func() error
	addr   func() string
}

func (this *listener[C]) Accept() (net.Conn, error) {
	result, err := this.accept()
	return result, err
}

func (this *listener[C]) Close() error {
	return this.close()
}

func (this *listener[C]) Addr() net.Addr {
	return addrAdapter(this.addr)
}

type addrAdapter func() string

func (this addrAdapter) Network() string {
	return this()
}

func (this addrAdapter) String() string {
	return this()
}
