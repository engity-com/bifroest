package service

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *service) onNewConnConnection(ctx ssh.Context, orig net.Conn) net.Conn {
	logger := this.Service.logger().WithAll(map[string]any{
		"local":      withLazyContextOrFieldExclude[net.Addr](ctx, ssh.ContextKeyLocalAddr),
		"remoteUser": withLazyContextOrFieldExclude[string](ctx, ssh.ContextKeyUser),
		"remote":     withLazyContextOrFieldExclude[net.Addr](ctx, ssh.ContextKeyRemoteAddr),
		"ssh":        withLazyContextOrFieldExclude[string](ctx, ssh.ContextKeySessionID),
		"session": fields.LazyFunc(func() any {
			auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
			if !ok {
				return fields.Exclude
			}
			sess := auth.FindSession()
			if sess == nil {
				return fields.Exclude
			}
			si, err := sess.Info(ctx)
			if err != nil {
				return fields.Exclude
			}
			return si.Id()
		}),
		"flow": fields.LazyFunc(func() any {
			auth, ok := ctx.Value(authorizationCtxKey).(authorization.Authorization)
			if !ok {
				return fields.Exclude
			}
			return auth.Flow()
		}),
	})

	wrapped, err := this.newConnection(orig, ctx, logger)
	if err != nil {
		logger.WithError(err).Error("cannot create wrap new connection")
		return nil
	}

	if wrapped != nil {
		logger.Debug("new connection started")
		ctx.SetValue(connectionCtxKey, wrapped)
	}

	return wrapped
}

func (this *service) newConnection(orig net.Conn, ctx ssh.Context, logger log.Logger) (net.Conn, error) {
	for {
		current := this.activeConnections.Load()
		if current >= int64(this.Configuration.Ssh.MaxConnections) {
			logger.
				With("max", this.Configuration.Ssh.MaxConnections).
				With("current", current).
				Info("max connections reached; closing forcibly")
			return nil, nil
		}
		if this.activeConnections.CompareAndSwap(current, current+1) {
			break
		}
	}

	id, err := bconn.NewId()
	if err != nil {
		return nil, err
	}

	now := time.Now().UnixMilli()
	result := &connection{
		Conn:    orig,
		id:      id,
		context: ctx,
		logger:  logger,
		service: this,
		created: now,
	}
	result.lastActivity.Store(now)
	return result, nil
}

type connection struct {
	net.Conn
	id      bconn.Id
	context ssh.Context
	logger  log.Logger
	service *service
	created int64

	interceptorP atomic.Pointer[session.ConnectionInterceptor]
	closed       atomic.Bool
	lastActivity atomic.Int64

	read    atomic.Int64
	written atomic.Int64
}

func (this *connection) Id() bconn.Id {
	return this.id
}

func (this *connection) Remote() bnet.Remote {
	return &remote{this.context}
}

func (this *connection) Logger() log.Logger {
	return this.logger
}

func (this *connection) doWithInterceptor(consumer func(session.ConnectionInterceptor) error) error {
	if v := this.interceptorP.Load(); v != nil {
		return consumer(*v)
	}

	auth, ok := this.context.Value(authorizationCtxKey).(authorization.Authorization)
	if !ok {
		// Authorization is not already resolved or the connection is anyway closed to being rejected...
		return nil
	}

	sess := auth.FindSession()
	if sess == nil {
		// Authorization does not have a session...
		return nil
	}

	v, err := sess.ConnectionInterceptor(this.context)
	if err != nil {
		if errors.Is(err, session.ErrMaxConnectionsPerSessionReached) && !this.closed.Load() {
			this.logger.Info("max connections per session reached; closing forcibly")
		}
		_ = this.Close()
		return err
	}

	if !this.interceptorP.CompareAndSwap(nil, &v) {
		// Concurrent operation happen - take the existing one and close the created.
		if err := v.Close(); err != nil {
			return err
		}
		return consumer(*this.interceptorP.Load())
	}

	return consumer(v)
}

func (this *connection) doWithInterceptorOnAction(op string, action func(session.ConnectionInterceptor, ssh.Context, log.Logger, net.Conn) (time.Time, session.ConnectionInterceptorResult, error)) error {
	var deadline time.Time
	var t connectionTimeType
	err := this.doWithInterceptor(func(v session.ConnectionInterceptor) error {
		ad, at, err := action(v, this.context, this.logger, this.Conn)
		if err != nil {
			return err
		}
		deadline = ad
		t = connectionTimeType(at)
		return nil
	})
	if err != nil {
		return err
	}

	doForceClose := func() error {
		this.logger.
			With("reason", t).
			Info("connection will be forcibly closed")
		if err := this.Conn.Close(); err != nil {
			return err
		}
		return &net.OpError{
			Op:     op,
			Net:    this.Conn.LocalAddr().Network(),
			Source: this.Conn.RemoteAddr(),
			Addr:   this.Conn.LocalAddr(),
			Err:    os.ErrDeadlineExceeded,
		}
	}
	if t == connectionValidityResultSessionDisposed {
		return doForceClose()
	}

	if v := this.service.Configuration.Ssh.IdleTimeout; !v.IsZero() {
		idleDeadline := time.UnixMilli(this.lastActivity.Load() + v.Native().Milliseconds())
		if deadline.IsZero() || deadline.After(idleDeadline) {
			deadline = idleDeadline
			t = connectionValidityResultConnectionIdle
		}
	}

	if v := this.service.Configuration.Ssh.MaxTimeout; !v.IsZero() {
		maxDeadline := time.UnixMilli(this.created + v.Native().Milliseconds())
		if deadline.IsZero() || deadline.After(maxDeadline) {
			deadline = maxDeadline
			t = connectionValidityResultConnectionMax
		}
	}

	if !deadline.IsZero() {
		if time.Now().After(deadline) {
			return doForceClose()
		} else if err := this.Conn.SetDeadline(deadline); err != nil {
			return err
		}
	}

	return nil
}

func (this *connection) Write(p []byte) (int, error) {
	if err := this.doWithInterceptorOnAction("write", session.ConnectionInterceptor.OnWriteConnection); err != nil {
		return 0, err
	}
	n, err := this.Conn.Write(p)
	this.written.Add(int64(n))
	return n, err
}

func (this *connection) Read(b []byte) (int, error) {
	if err := this.doWithInterceptorOnAction("read", session.ConnectionInterceptor.OnReadConnection); err != nil {
		return 0, err
	}
	n, err := this.Conn.Read(b)
	this.read.Add(int64(n))
	return n, err
}

func (this *connection) Close() (rErr error) {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	defer func(target *error) {
		if err := this.doWithInterceptor(session.ConnectionInterceptor.Close); err != nil && *target == nil {
			*target = err
		}
	}(&rErr)
	if v := this.service.activeConnections.Add(-1); v < 0 {
		panic(fmt.Errorf("trying to close more connections that are actually opened; currently: %d", v))
	}

	return this.Conn.Close()
}

func (this *connection) SetDeadline(time.Time) error {
	// We'll ignore them, because this should be handled only by session.ConnectionInterceptor.
	return nil
}

func (this *connection) SetReadDeadline(v time.Time) error {
	return this.SetDeadline(v)
}

func (this *connection) SetWriteDeadline(v time.Time) error {
	return this.SetDeadline(v)
}

type connectionTimeType uint8

const (
	connectionValidityResultNone                               = connectionTimeType(session.ConnectionInterceptorResultNone)
	connectionValidityResultSessionIdle                        = connectionTimeType(session.ConnectionInterceptorResultIdle)
	connectionValidityResultSessionMax                         = connectionTimeType(session.ConnectionInterceptorResultMax)
	connectionValidityResultSessionDisposed                    = connectionTimeType(session.ConnectionInterceptorResultDisposed)
	connectionValidityResultConnectionIdle  connectionTimeType = iota
	connectionValidityResultConnectionMax
)

func (this connectionTimeType) String() string {
	switch this {
	case connectionValidityResultNone:
		return "none"
	case connectionValidityResultSessionIdle:
		return "session-idle"
	case connectionValidityResultSessionMax:
		return "session-max-age"
	case connectionValidityResultSessionDisposed:
		return "session-disposed"
	case connectionValidityResultConnectionIdle:
		return "connection-idle"
	case connectionValidityResultConnectionMax:
		return "connection-max-age"
	default:
		return strconv.FormatUint(uint64(this), 10)
	}
}
