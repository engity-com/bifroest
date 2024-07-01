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

	OnReadConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorResult, error)
	OnWriteConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorResult, error)
}

type ConnectionInterceptorResult uint8

const (
	ConnectionInterceptorResultNone ConnectionInterceptorResult = iota
	ConnectionInterceptorResultIdle
	ConnectionInterceptorResultMax
	ConnectionInterceptorResultDisposed
)
