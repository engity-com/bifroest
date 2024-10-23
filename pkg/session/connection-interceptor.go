package session

import (
	"io"
	gonet "net"
	"time"

	log "github.com/echocat/slf4g"
	glssh "github.com/gliderlabs/ssh"
)

type ConnectionInterceptor interface {
	io.Closer

	OnReadConnection(glssh.Context, log.Logger, gonet.Conn) (time.Time, ConnectionInterceptorResult, error)
	OnWriteConnection(glssh.Context, log.Logger, gonet.Conn) (time.Time, ConnectionInterceptorResult, error)
}

type ConnectionInterceptorResult uint8

const (
	ConnectionInterceptorResultNone ConnectionInterceptorResult = iota
	ConnectionInterceptorResultIdle
	ConnectionInterceptorResultMax
	ConnectionInterceptorResultDisposed
)
