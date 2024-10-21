package net

import (
	"net"

	"github.com/engity-com/bifroest/pkg/sys"
)

type CloseWriterConn interface {
	net.Conn
	sys.CloseWriter
}

func AsCloseWriterConn(conn net.Conn) CloseWriterConn {
	if v, ok := conn.(CloseWriterConn); ok {
		return v
	}
	return &closeWriterConn{conn}
}

type closeWriterConn struct {
	net.Conn
}

func (this *closeWriterConn) CloseWrite() error {
	return this.Close()
}
