package session

import (
	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
	"net"
	"time"
)

func (this *simple) ConnectionInterceptor() (ConnectionInterceptor, error) {
	return &simpleConnectionInterceptor{}, nil
}

type simpleConnectionInterceptor struct{}

func (this *simpleConnectionInterceptor) Close() error {
	return nil
}

func (this *simpleConnectionInterceptor) OnReadConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorTimeType, error) {
	return time.Time{}, 0, nil
}

func (this *simpleConnectionInterceptor) OnWriteConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorTimeType, error) {
	return time.Time{}, 0, nil
}
