package session

import (
	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
	"io"
	"net"
	"time"
)

type ConnectionInterceptor interface {
	io.Closer

	OnReadConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorTimeType, error)
	OnWriteConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorTimeType, error)
}

type ConnectionInterceptorTimeType uint8

const (
	ConnectionInterceptorTimeTypeNone ConnectionInterceptorTimeType = iota
	ConnectionInterceptorTimeTypeIdle
	ConnectionInterceptorTimeTypeMax
)
