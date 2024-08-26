package environment

import (
	"io"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/gliderlabs/ssh"
)

type dummyTtySession interface {
	io.ReadWriter
	Context() ssh.Context
}

type dummyTty struct {
	session dummyTtySession

	environment   *dummy
	windowChannel <-chan ssh.Window

	onNotifyResize func()
	window         ssh.Window

	mutex sync.RWMutex
}

func (this *dummyTty) Start() error {
	go func() {
		for {
			select {
			case <-this.session.Context().Done():
				return
			case v, ok := <-this.windowChannel:
				if !ok {
					return
				}
				this.windowChanged(v)
			}
		}
	}()

	return nil
}

func (this *dummyTty) Stop() error {
	return nil
}

func (this *dummyTty) Drain() error {
	return nil
}

func (this *dummyTty) NotifyResize(cb func()) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.onNotifyResize = cb
}

func (this *dummyTty) windowChanged(v ssh.Window) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.window = v
	if cb := this.onNotifyResize; cb != nil {
		cb()
	}
}

func (this *dummyTty) WindowSize() (tcell.WindowSize, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	return tcell.WindowSize{
		Width:  this.window.Width,
		Height: this.window.Height,
	}, nil
}

func (this *dummyTty) Read(p []byte) (n int, err error) {
	return this.session.Read(p)
}

func (this *dummyTty) Write(p []byte) (n int, err error) {
	return this.session.Write(p)
}

func (this *dummyTty) Close() error {
	return nil
}
