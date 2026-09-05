package session

import (
	"io"
	gonet "net"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
)

type ConnectionInterceptor interface {
	io.Closer

	OnReadConnection(essh.Context, log.Logger, gonet.Conn) (time.Time, ConnectionInterceptorResult, error)
	OnWriteConnection(essh.Context, log.Logger, gonet.Conn) (time.Time, ConnectionInterceptorResult, error)
}

type ConnectionInterceptorResult uint8

const (
	ConnectionInterceptorResultNone ConnectionInterceptorResult = iota
	ConnectionInterceptorResultIdle
	ConnectionInterceptorResultMax
	ConnectionInterceptorResultDisposed
)
