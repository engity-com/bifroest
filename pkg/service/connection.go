package service

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/gliderlabs/ssh"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

func (this *service) newConnection(orig net.Conn, ctx ssh.Context, logger log.Logger) (net.Conn, error) {
	now := time.Now().UnixMilli()
	result := &connection{
		Conn:    orig,
		context: ctx,
		logger:  logger,
		service: this,
		created: now,
	}
	result.lastActivity.Store(now)

	runtime.SetFinalizer(result, func(c *connection) {
		logger.Info("bye via finalizer")
		_ = c.Close()
	})
	return result, nil
}

type connection struct {
	net.Conn
	context ssh.Context
	logger  log.Logger
	service *service
	created int64

	interceptorP atomic.Pointer[session.ConnectionInterceptor]
	closed       atomic.Bool
	lastActivity atomic.Int64
}

func (this *connection) doWithInterceptor(consumer func(session.ConnectionInterceptor) error) error {
	if v := this.interceptorP.Load(); v != nil {
		return consumer(*v)
	}

	sess, ok := this.context.Value(sessionCtxKey).(session.Session)
	if !ok {
		// Session is not already resolved or the connection is anyway closed to being rejected...
		return nil
	}

	v, err := sess.ConnectionInterceptor()
	if err != nil {
		if errors.Is(err, session.ErrMaxConnectionsPerSessionReached) {
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

func (this *connection) doWithInterceptorOnAction(op string, action func(session.ConnectionInterceptor, ssh.Context, log.Logger, net.Conn) (time.Time, session.ConnectionInterceptorTimeType, error)) error {
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

	if v := this.service.Configuration.Ssh.IdleTimeout; !v.IsZero() {
		idleDeadline := time.UnixMilli(this.lastActivity.Load() + v.Native().Milliseconds())
		if deadline.IsZero() || deadline.After(idleDeadline) {
			deadline = idleDeadline
			t = connectionTimeTypeConnectionIdle
		}
	}

	if v := this.service.Configuration.Ssh.MaxTimeout; !v.IsZero() {
		maxDeadline := time.UnixMilli(this.created + v.Native().Milliseconds())
		if deadline.IsZero() || deadline.After(maxDeadline) {
			deadline = maxDeadline
			t = connectionTimeTypeConnectionMax
		}
	}

	if !deadline.IsZero() {
		if time.Now().After(deadline) {
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
	return this.Conn.Write(p)
}

func (this *connection) Read(b []byte) (int, error) {
	if err := this.doWithInterceptorOnAction("read", session.ConnectionInterceptor.OnReadConnection); err != nil {
		return 0, err
	}
	return this.Conn.Read(b)
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
	connectionTimeTypeNone                              = connectionTimeType(session.ConnectionInterceptorTimeTypeNone)
	connectionTimeTypeSessionIdle                       = connectionTimeType(session.ConnectionInterceptorTimeTypeIdle)
	connectionTimeTypeSessionMax                        = connectionTimeType(session.ConnectionInterceptorTimeTypeMax)
	connectionTimeTypeConnectionIdle connectionTimeType = iota
	connectionTimeTypeConnectionMax
)

func (this connectionTimeType) String() string {
	switch this {
	case connectionTimeTypeNone:
		return "none"
	case connectionTimeTypeSessionIdle:
		return "session-idle"
	case connectionTimeTypeSessionMax:
		return "session-max-age"
	case connectionTimeTypeConnectionIdle:
		return "connection-idle"
	case connectionTimeTypeConnectionMax:
		return "connection-max-age"
	default:
		return strconv.FormatUint(uint64(this), 10)
	}
}
