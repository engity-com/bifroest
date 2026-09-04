package service

import (
	"sync"
	"time"
)

type connectionLifecycle struct {
	mutex     sync.Mutex
	accepting bool
	active    int
	drained   chan struct{}
}

func newConnectionLifecycle() *connectionLifecycle {
	return &connectionLifecycle{
		accepting: true,
		drained:   make(chan struct{}),
	}
}

func (this *connectionLifecycle) register() (release func(), ok bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.accepting {
		return nil, false
	}
	this.active++
	return sync.OnceFunc(func() {
		this.mutex.Lock()
		defer this.mutex.Unlock()
		this.active--
		this.closeDrainedIfDone()
	}), true
}

func (this *connectionLifecycle) stop() {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if !this.accepting {
		return
	}
	this.accepting = false
	this.closeDrainedIfDone()
}

func (this *connectionLifecycle) wait(timeout time.Duration) bool {
	this.stop()
	this.mutex.Lock()
	drained := this.drained
	this.mutex.Unlock()
	if timeout <= 0 {
		select {
		case <-drained:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
		return true
	case <-timer.C:
		return false
	}
}

func (this *connectionLifecycle) waitUntilDrained() {
	this.stop()
	<-this.drained
}

func (this *connectionLifecycle) closeDrainedIfDone() {
	if this.accepting || this.active != 0 {
		return
	}
	select {
	case <-this.drained:
	default:
		close(this.drained)
	}
}
