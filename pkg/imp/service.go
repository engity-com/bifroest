package imp

import (
	"context"
	"net"

	log "github.com/echocat/slf4g"
	"github.com/things-go/go-socks5"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

type Service struct {
	Conn   net.Conn
	Logger log.Logger
}

func (this *Service) conn() net.Conn {
	if v := this.Conn; v != nil {
		return v
	}
	return stdinoutConnection
}

func (this *Service) Run(ctx context.Context) error {
	fail := func(err error) error {
		return err
	}

	instance, err := this.createInstance()
	if err != nil {
		return fail(err)
	}

	return instance.run(ctx)
}

func (this *Service) createInstance() (*service, error) {
	result := service{
		Service: this,
	}

	result.socks5Server = socks5.NewServer(
		socks5.WithLogger(log.NewLoggerFacade(result.coreLogger)),
	)

	return &result, nil
}

func (this *Service) coreLogger() log.CoreLogger {
	return this.logger()
}

func (this *Service) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("socks5")
}

type service struct {
	*Service

	socks5Server *socks5.Server
}

func (this *service) run(ctx context.Context) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	ln, err := net.Listen("tcp", this.Address)
	if err != nil {
		return failf("cannot listen on %q: %w", this.Address, err)
	}
	defer common.IgnoreCloseError(ln)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if err := this.serve(ln); err != nil {
		return fail(err)
	}

	return nil
}

func (this *service) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			l := this.logger().With("remote", conn.RemoteAddr())
			l.Info("remote connected to socks5")
			if err := this.socks5Server.ServeConn(conn); err != nil {
				l.WithError(err).Warn("failed to handle socks5 connection")
			} else {
				l.Info("remote disconnected from socks5")
			}
		}()
	}
}
