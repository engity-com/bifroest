package net

import (
	gonet "net"
)

type CloseWriterConn interface {
	gonet.Conn
	CloseWrite() error
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
