package service

import (
	"context"
	goerrors "errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/engity-com/bifroest/pkg/authorization"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type terminalTransport interface {
	bconn.LifetimeAware
	io.Closer
}

// terminalConnection is a neutral post-authentication lease, not a browser
// credential. Its historical name also covers structured management requests.
// The transport owns status delivery and must Close after its execution ends.
// Reconnects acquire a new lease; they never attach to a previous execution.
type terminalConnection struct {
	terminalTransport
	service       *service
	authorization authorization.Authorization
	session       session.Session
	lease         session.ActivityInterceptor
	ctx           context.Context
	cancel        context.CancelFunc
	closed        atomic.Bool
	used          atomic.Bool
	activityMutex sync.Mutex
	wake          chan struct{}
	done          chan struct{}
	release       func()
	stopShutdown  func() bool
}

func (this *terminalConnection) Lifetime() context.Context { return this.ctx }
func (this *terminalConnection) IsClosed() bool            { return this.closed.Load() }

func (this *service) registerTerminalConnection(transport terminalTransport, auth authorization.Authorization) (*terminalConnection, error) {
	if isNilDependency(transport) || isNilDependency(transport.Lifetime()) || auth == nil || !auth.IsAuthorized() || auth.FindSession() == nil || auth.Flow() != auth.FindSession().Flow() {
		return nil, errors.Permission.Newf("terminal connection requires a verified authorization and session")
	}
	ctx := transport.Lifetime()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if this.terminalAdmissions != nil {
		release, ok := this.terminalAdmissions.register()
		if !ok {
			return nil, context.Canceled
		}
		defer release()
	}
	ctx, cancel := context.WithCancel(ctx)
	stopShutdown := func() bool { return false }
	if this.terminalContext != nil {
		stopShutdown = context.AfterFunc(this.terminalContext, cancel)
	}
	transferred := false
	defer func() {
		if !transferred {
			cancel()
			stopShutdown()
		}
	}()
	release := func() {}
	if this.connectionLifecycle != nil {
		var ok bool
		release, ok = this.connectionLifecycle.register()
		if !ok {
			return nil, context.Canceled
		}
	}
	owned := false
	defer func() {
		if !owned {
			release()
		}
	}()
	base := environmentContext{service: this, connection: transport, authorization: auth, executionContext: ctx}
	if err := this.validateTerminalAuthorization(&base); err != nil {
		return nil, err
	}
	lease, err := auth.FindSession().ConnectionInterceptor(ctx)
	if err != nil {
		return nil, err
	}
	activity, ok := lease.(session.ActivityInterceptor)
	if !ok || isNilDependency(activity) {
		_ = lease.Close()
		return nil, errors.System.Newf("session repository does not support neutral connection activity")
	}
	result := &terminalConnection{terminalTransport: transport, service: this, authorization: auth, session: auth.FindSession(), lease: activity, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), release: release, stopShutdown: stopShutdown}
	result.ctx = context.WithValue(ctx, auditConnectionContextKey{}, result)
	if err := result.check(false); err != nil {
		cancel()
		_ = activity.Close()
		return nil, err
	}
	owned = true
	transferred = true
	go result.watch()
	this.sessionConnections.track(result, result.session)
	if result.IsClosed() {
		<-result.done
		return nil, errors.Permission.Newf("session access has been revoked")
	}
	this.oidcRefresh.register(result.session)
	return result, nil
}

func (this *service) validateTerminalAuthorization(base *environmentContext) error {
	sess := base.Authorization().FindSession()
	if valid, err := session.IsStillValid(base.Context(), sess); err != nil {
		return err
	} else if !valid {
		return errors.Permission.Newf("session is no longer valid")
	}
	request := &authorizeRequest{service: this, connection: base.connection, authorization: base.Authorization()}
	repository := &compatibleSessionRepository{environments: this.environments, authorizeRequest: request}
	if compatible, err := repository.associationCompatible(base.Context(), sess); err != nil {
		return err
	} else if !compatible {
		return errors.Permission.Newf("session identity or target is incompatible")
	}
	if accepted, err := this.environments.WillBeAccepted(base); err != nil {
		return err
	} else if !accepted {
		return errors.Permission.Newf("terminal authorization is not accepted by the environment")
	}
	if compatible, err := this.associationEnvironmentCompatible(base.Context(), base, sess); err != nil {
		return err
	} else if !compatible {
		return errors.Permission.Newf("terminal session environment is incompatible")
	}
	return nil
}

func (this *terminalConnection) check(activity bool) error {
	this.activityMutex.Lock()
	defer this.activityMutex.Unlock()
	if this.IsClosed() {
		return context.Canceled
	}
	var deadline time.Time
	var result session.ConnectionInterceptorResult
	var err error
	if activity {
		deadline, result, err = this.lease.OnActivity(this.ctx)
	} else {
		deadline, result, err = this.lease.Check(this.ctx)
	}
	if err != nil {
		return err
	}
	if result == session.ConnectionInterceptorResultDisposed || !deadline.IsZero() && !time.Now().Before(deadline) {
		return errors.Permission.Newf("terminal session is disposed or expired")
	}
	return nil
}

func (this *terminalConnection) activity() error {
	if err := this.check(true); err != nil {
		_ = this.Close()
		return err
	}
	select {
	case this.wake <- struct{}{}:
	default:
	}
	return nil
}

func (this *terminalConnection) watch() {
	defer close(this.done)
	defer func() { _ = this.Close() }()
	for {
		this.activityMutex.Lock()
		deadline, result, err := this.lease.Check(this.ctx)
		this.activityMutex.Unlock()
		if err != nil || result == session.ConnectionInterceptorResultDisposed || !deadline.IsZero() && !time.Now().Before(deadline) {
			return
		}
		wait := time.Second // Detect direct session disposal even without transport I/O.
		if !deadline.IsZero() {
			wait = min(wait, time.Until(deadline))
		}
		timer := time.NewTimer(wait)
		select {
		case <-this.ctx.Done():
			timer.Stop()
			return
		case <-this.wake:
		case <-timer.C:
		}
		timer.Stop()
	}
}

func (this *terminalConnection) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	defer this.release()
	this.cancel()
	this.stopShutdown()
	this.service.sessionConnections.untrack(this)
	// Unblock transport I/O before potentially slower repository cleanup.
	transportErr := this.terminalTransport.Close()
	this.activityMutex.Lock()
	leaseErr := this.lease.Close()
	this.activityMutex.Unlock()
	return goerrors.Join(transportErr, leaseErr)
}
