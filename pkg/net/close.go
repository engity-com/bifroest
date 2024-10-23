package net

import (
	gonet "net"

	"github.com/engity-com/bifroest/pkg/sys"
)

type CloseWriterConn interface {
	gonet.Conn
	sys.CloseWriter
}

func AsCloseWriterConn(conn gonet.Conn) CloseWriterConn {
	if v, ok := conn.(CloseWriterConn); ok {
		return v
	}
	return &closeWriterConn{conn}
}

type closeWriterConn struct {
	gonet.Conn
}

func (this *closeWriterConn) CloseWrite() error {
	return this.Close()
}
