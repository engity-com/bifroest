package protocol

import (
	"bytes"
	"context"
	"io"
	gonet "net"
	"sync/atomic"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/google/uuid"
	"github.com/xtaci/smux"
	"golang.org/x/net/proxy"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp/logger"
	"github.com/engity-com/bifroest/pkg/net"
)

type Server struct {
	Version       common.Version
	ExpectedToken []byte

	Dialer proxy.ContextDialer

	DefaultLoggerProvider log.Provider
	Logger                log.Logger

	loggerProviderFacade atomic.Pointer[logger.ProviderFacade]
}

type errorEvent struct {
	connectionId     uuid.UUID
	connectionPartId uint32
	error            error
}

func (this *Server) Serve(ctx context.Context, ln gonet.Listener) error {
	fail := func(err error) error {
		return err
	}

	l := this.logger()
	for ctx.Err() == nil {
		c, err := ln.Accept()
		if net.IsClosedError(err) {
			break
		}
		if err != nil {
			return fail(err)
		}
		lvl, sessionId, err := handleHandshakeFromServerSide(this.ExpectedToken, c)
		if !bytes.Equal(sessionId[:], uuid.Nil[:]) {
			l = l.With("sessionId", sessionId)
		}
		if errors.Is(err, ErrHandshakeProtocolMismatch) {
			l.Warn("incompatible endpoint has tried to connect - maybe someone who tries to access stdin/stdout directly; ignoring...")
			continue
		}
		if err != nil {
			return fail(err)
		}
		l.Info("client successfully connected")
		if err := this.serveConnAfterHandshake(ctx, lvl, c, sessionId); err != nil {
			return fail(err)
		}
		l.Info("client disconnected")
		break
	}
	return nil
}

func (this *Server) serveConnAfterHandshake(ctx context.Context, lvl level.Level, mainConn io.ReadWriteCloser, sessionId uuid.UUID) error {
	fail := func(err error) error {
		return err
	}

	sess, err := smux.Server(mainConn, smuxConfig)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseError(sess)

	errs := make(chan *errorEvent)
	defer close(errs)

	returnConn, err := sess.Accept()
	if err != nil {
		return fail(err)
	}
	go this.serveLoggingAndErrors(ctx, returnConn, errs, lvl)

	for ctx.Err() == nil {
		stream, err := sess.AcceptStream()
		if net.IsClosedError(err) {
			break
		}
		if err != nil {
			return fail(err)
		}

		go func(stream *smux.Stream) {
			defer common.IgnoreCloseError(stream)
			streamContext, cancelFunc := context.WithCancel(ctx)

			go func(stream *smux.Stream) {
				dieChan := stream.GetDieCh()
				<-dieChan
				cancelFunc()
			}(stream)

			this.parseAndServe(streamContext, stream, errs, sessionId)
		}(stream)
	}
	return nil
}

func (this *Server) parseAndServe(ctx context.Context, plainConn *smux.Stream, errs chan *errorEvent, sessionId uuid.UUID) struct{} {
	var connectionId uuid.UUID

	fail := func(err error) struct{} {
		errs <- &errorEvent{connectionId, plainConn.ID(), err}
		return struct{}{}
	}
	try := func(err error) struct{} {
		if err != nil {
			return fail(err)
		}
		return struct{}{}
	}

	if n, err := plainConn.Read(connectionId[:]); err != nil {
		return fail(err)
	} else if n != len(connectionId[:]) {
		return fail(io.ErrUnexpectedEOF)
	} else if connectionId.Variant() != uuid.RFC4122 {
		return fail(errors.Network.Newf("illegal connection id: %v", connectionId))
	}

	var m Method
	if err := m.Read(plainConn); err != nil {
		return fail(err)
	}

	var c Conn = &conn{this.getLoggerProviderFacade(), plainConn, connectionId, sessionId}
	switch m {
	case MethodEcho:
		return try(this.parseAndHandleMethodEcho(ctx, c))
	case MethodDirectTcp:
		return try(this.parseAndHandleMethodDirectTcp(ctx, c))
	case MethodAgentForward:
		return try(this.parseAndHandleMethodAgentForward(ctx, c))
	case MethodKill:
		return try(this.parseAndHandleMethodKill(ctx, c))
	case MethodExit:
		return try(this.parseAndHandleMethodExit(ctx, c))
	default:
		return fail(errors.System.Newf("%w: %v", ErrIllegalMethod, m))
	}
}

func (this *Server) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("imp-protocol-server")
}

func (this *Server) dialer() proxy.ContextDialer {
	if v := this.Dialer; v != nil {
		return v
	}
	return defaultDialer
}

func (this *Server) getLoggerProviderFacade() *logger.ProviderFacade {
	for {
		if v := this.loggerProviderFacade.Load(); v != nil {
			return v
		}
		v := &logger.ProviderFacade{}
		v.Set(this.getDefaultLoggerProvider())
		if this.loggerProviderFacade.CompareAndSwap(nil, v) {
			return v
		}
	}
}

func (this *Server) getDefaultLoggerProvider() log.Provider {
	if v := this.DefaultLoggerProvider; v != nil {
		return v
	}
	return log.GetProvider()
}

var defaultDialer = &gonet.Dialer{}
