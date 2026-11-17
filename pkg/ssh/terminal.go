package ssh

import (
	"context"
	"io"
	"sync"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// Terminal adapts an existing SSH channel to execution I/O, not the other way
// around. Stop releases control workers without closing the channel before its
// SSH exit status has been sent. The execution owner must call Stop.
type Terminal struct {
	session      essh.Session
	ctx          context.Context
	cancel       context.CancelFunc
	ptyOnce      sync.Once
	pty          terminal.Pty
	windows      <-chan terminal.Window
	hasPty       bool
	workers      sync.WaitGroup
	controlMutex sync.Mutex
	signalMutex  sync.Mutex
	signalStop   chan struct{}
	signalDone   chan struct{}
}

func NewTerminal(ctx context.Context, session essh.Session) *Terminal {
	ctx, cancel := context.WithCancel(ctx)
	return &Terminal{session: session, ctx: ctx, cancel: cancel}
}

func (this *Terminal) Context() context.Context       { return this.ctx }
func (this *Terminal) Read(data []byte) (int, error)  { return this.session.Read(data) }
func (this *Terminal) Write(data []byte) (int, error) { return this.session.Write(data) }
func (this *Terminal) Stderr() io.ReadWriter          { return this.session.Stderr() }
func (this *Terminal) RawCommand() string             { return this.session.RawCommand() }
func (this *Terminal) Environ() []string              { return this.session.Environ() }
func (this *Terminal) CloseWrite() error              { return this.session.CloseWrite() }
func (this *Terminal) Close() error                   { this.cancel(); return this.session.Close() }
func (this *Terminal) Stop() {
	this.controlMutex.Lock()
	this.cancel()
	this.controlMutex.Unlock()
	this.Signals(nil)
	this.workers.Wait()
}

func (this *Terminal) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	this.ptyOnce.Do(func() {
		this.controlMutex.Lock()
		defer this.controlMutex.Unlock()
		pty, source, ok := this.session.Pty()
		this.pty, this.hasPty = TerminalPty(pty), ok
		if !ok || source == nil || this.ctx.Err() != nil {
			return
		}
		target := make(chan terminal.Window, 1)
		this.windows = target
		this.workers.Add(1)
		go func() {
			defer this.workers.Done()
			defer close(target)
			for {
				select {
				case <-this.ctx.Done():
					return
				case value, open := <-source:
					if !open {
						return
					}
					select {
					case target <- TerminalWindow(value):
					case <-this.ctx.Done():
						return
					}
				}
			}
		}()
	})
	return terminal.ClonePty(this.pty), this.windows, this.hasPty
}

func (this *Terminal) Signals(target chan<- terminal.Signal) {
	this.signalMutex.Lock()
	defer this.signalMutex.Unlock()
	if this.signalStop != nil {
		this.session.Signals(nil)
		close(this.signalStop)
		<-this.signalDone
		this.signalStop = nil
	}
	if target == nil || this.ctx.Err() != nil {
		return
	}
	source := make(chan essh.Signal, 16)
	stop, done := make(chan struct{}), make(chan struct{})
	this.signalStop, this.signalDone = stop, done
	this.session.Signals(source)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-this.ctx.Done():
				return
			case value, open := <-source:
				if !open {
					return
				}
				select {
				case target <- terminal.Signal(value):
				case <-stop:
					return
				case <-this.ctx.Done():
					return
				}
			}
		}
	}()
}

type terminalEnvironmentLayers interface {
	ClientEnvironment() []string
	AuthorizedKeyEnvironment() sys.EnvVars
}

func (this *Terminal) ClientEnvironment() []string {
	if provider, ok := this.session.(terminalEnvironmentLayers); ok {
		return append([]string(nil), provider.ClientEnvironment()...)
	}
	return append([]string(nil), this.session.Environ()...)
}
func (this *Terminal) AuthorizedKeyEnvironment() sys.EnvVars {
	if provider, ok := this.session.(terminalEnvironmentLayers); ok {
		return provider.AuthorizedKeyEnvironment().Clone()
	}
	return nil
}
func (this *Terminal) OriginalCommand() (string, bool) {
	if provider, ok := this.session.(interface{ OriginalCommand() (string, bool) }); ok {
		return provider.OriginalCommand()
	}
	return "", false
}

func TerminalWindow(value essh.Window) terminal.Window { return terminal.Window(value) }
func SshWindow(value terminal.Window) essh.Window      { return essh.Window(value) }
func TerminalPty(value essh.Pty) terminal.Pty {
	return terminal.ClonePty(terminal.Pty{Term: value.Term, Window: TerminalWindow(value.Window), TerminalModes: value.TerminalModes})
}
func SshPty(value terminal.Pty) essh.Pty {
	value = terminal.ClonePty(value)
	return essh.Pty{Term: value.Term, Window: SshWindow(value.Window), TerminalModes: value.TerminalModes}
}
