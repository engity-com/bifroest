package session

import (
	"io"
	"net"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
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
