package session

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func (this *fs) ConnectionInterceptor(context.Context) (ConnectionInterceptor, error) {
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	if this.repository.connectionInterceptors == nil {
		this.repository.connectionInterceptors = make(fsConnectionInterceptors)
	}

	byFlow, hasByFlow := this.repository.connectionInterceptors[this.flow]
	if !hasByFlow {
		byFlow = make(map[uuid.UUID]*fsConnectionInterceptorStack)
		this.repository.connectionInterceptors[this.flow] = byFlow
	}

	byId, hasById := byFlow[this.id]
	if !hasById {
		byId = &fsConnectionInterceptorStack{
			repository: this.repository,
			flow:       this.flow,
			id:         this.id,
			created:    time.Now().UnixMilli(),
		}
		byId.lastActivity.Store(time.Now().UnixMilli())
		byFlow[this.id] = byId
	}

	return byId.create()
}

type fsConnectionInterceptors map[configuration.FlowName]map[uuid.UUID]*fsConnectionInterceptorStack

type fsConnectionInterceptorStack struct {
	repository *FsRepository
	flow       configuration.FlowName
	id         uuid.UUID
	created    int64
	active     atomic.Int32

	lastActivity atomic.Int64
	disposed     atomic.Bool
}

func (this *fsConnectionInterceptorStack) create() (*fsConnectionInterceptor, error) {
	n := this.active.Add(1)
	if v := this.repository.conf.MaxConnections; v > 0 && n > int32(v) {
		this.active.Add(-1)
		return nil, ErrMaxConnectionsPerSessionReached
	}

	return &fsConnectionInterceptor{fsConnectionInterceptorStack: this}, nil
}

func (this *fsConnectionInterceptorStack) close() error {
	if n := this.active.Add(-1); n < 0 {
		panic("closed more where created")
	} else if n > 0 {
		// Still others open, let it open...
		return nil
	}

	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()

	if this.repository.connectionInterceptors == nil {
		panic("this connectionInterceptors is nil, before this instance was closed")
	}

	byFlow, hasByFlow := this.repository.connectionInterceptors[this.flow]
	if !hasByFlow {
		panic(fmt.Errorf("connectionInterceptors[%v] is nil, before this instance was closed", this.flow))
	}

	delete(byFlow, this.id)
	if len(byFlow) == 0 {
		delete(this.repository.connectionInterceptors, this.flow)
	}

	return nil
}

func (this *fsConnectionInterceptorStack) OnReadConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorResult, error) {
	return this.onConnectionAction()
}

func (this *fsConnectionInterceptorStack) OnWriteConnection(ssh.Context, log.Logger, net.Conn) (time.Time, ConnectionInterceptorResult, error) {
	return this.onConnectionAction()
}

func (this *fsConnectionInterceptorStack) onConnectionAction() (time.Time, ConnectionInterceptorResult, error) {
	if this.disposed.Load() {
		return time.Time{}, ConnectionInterceptorResultDisposed, nil
	}
	var deadline time.Time
	var t ConnectionInterceptorResult
	if v := this.repository.conf.IdleTimeout; !v.IsZero() {
		deadline = time.UnixMilli(this.lastActivity.Load() + v.Native().Milliseconds())
		t = ConnectionInterceptorResultIdle
	}

	if v := this.repository.conf.MaxTimeout; !v.IsZero() {
		maxDeadline := time.UnixMilli(this.created + v.Native().Milliseconds())
		if deadline.IsZero() || deadline.After(maxDeadline) {
			deadline = maxDeadline
			t = ConnectionInterceptorResultMax
		}
	}

	return deadline, t, nil
}

type fsConnectionInterceptor struct {
	*fsConnectionInterceptorStack
	closed atomic.Bool
}

func (this *fsConnectionInterceptor) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		// Already closed
		return nil
	}
	return this.fsConnectionInterceptorStack.close()
}
