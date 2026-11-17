package session

import (
	"context"
	"io"
	gonet "net"
	"time"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
)

// ActivityInterceptor is an optional transport-neutral extension. Check reads
// validity without renewing idle time; OnActivity may touch shared last access.
// The same underlying lease/count must be used for SSH and neutral connections.
type ActivityInterceptor interface {
	io.Closer
	Check(context.Context) (time.Time, ConnectionInterceptorResult, error)
	OnActivity(context.Context) (time.Time, ConnectionInterceptorResult, error)
}

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
