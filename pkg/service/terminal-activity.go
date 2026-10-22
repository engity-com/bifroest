package service

import (
	"context"
	"io"
	"sync"

	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// Activity follows real execution I/O and control events. Validity watches never
// renew idle time. Both control queues are bounded and their workers are joined.
type activityTerminal struct {
	terminal.Stream
	connection             *terminalConnection
	snapshot               terminalRecordingPty
	ctx                    context.Context
	cancel                 context.CancelFunc
	windows                <-chan terminal.Window
	done                   chan struct{}
	signalMutex            sync.Mutex
	signalStop, signalDone chan struct{}
	stderr                 *activityTerminalStderr
}

func newActivityTerminal(conn *terminalConnection, stream terminal.Stream, snapshot terminalRecordingPty) *activityTerminal {
	ctx, cancel := context.WithCancel(conn.Lifetime())
	result := &activityTerminal{Stream: stream, connection: conn, snapshot: snapshot, ctx: ctx, cancel: cancel, done: make(chan struct{})}
	result.stderr = &activityTerminalStderr{terminal: result, stream: stream.Stderr()}
	if snapshot.hasPty && snapshot.windows != nil {
		target := make(chan terminal.Window, 1)
		result.windows = target
		go func() {
			defer close(result.done)
			defer close(target)
			for {
				select {
				case <-ctx.Done():
					return
				case window, open := <-snapshot.windows:
					if !open {
						return
					}
					if err := validateTerminalWindow(window); err != nil {
						_ = conn.Close()
						return
					}
					if err := conn.activity(); err != nil {
						return
					}
					select {
					case target <- window:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	} else {
		close(result.done)
	}
	return result
}
func (this *activityTerminal) stop()        { this.cancel(); this.Signals(nil); <-this.done }
func (this *activityTerminal) Close() error { return this.connection.Close() }
func (this *activityTerminal) Read(data []byte) (int, error) {
	if err := this.connection.activity(); err != nil {
		return 0, err
	}
	n, err := this.Stream.Read(data)
	if n > 0 {
		if activityErr := this.connection.activity(); activityErr != nil {
			return 0, activityErr
		}
	}
	return n, err
}
func (this *activityTerminal) Write(data []byte) (int, error) {
	if err := this.connection.activity(); err != nil {
		return 0, err
	}
	return this.Stream.Write(data)
}
func (this *activityTerminal) Stderr() io.ReadWriter { return this.stderr }
func (this *activityTerminal) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	return terminal.ClonePty(this.snapshot.pty), this.windows, this.snapshot.hasPty
}
func (this *activityTerminal) Signals(target chan<- terminal.Signal) {
	this.signalMutex.Lock()
	defer this.signalMutex.Unlock()
	if this.signalStop != nil {
		this.Stream.Signals(nil)
		close(this.signalStop)
		<-this.signalDone
		this.signalStop = nil
	}
	if target == nil || this.ctx.Err() != nil {
		return
	}
	source := make(chan terminal.Signal, 16)
	stop, done := make(chan struct{}), make(chan struct{})
	this.signalStop, this.signalDone = stop, done
	this.Stream.Signals(source)
	go func() {
		defer close(done)
		for {
			select {
			case <-this.ctx.Done():
				return
			case <-stop:
				return
			case signal, open := <-source:
				if !open {
					return
				}
				normalized, valid := normalizedTerminalSignal(signal)
				if !valid {
					_ = this.connection.Close()
					return
				}
				if err := this.connection.activity(); err != nil {
					return
				}
				select {
				case target <- normalized:
				case <-this.ctx.Done():
					return
				case <-stop:
					return
				}
			}
		}
	}()
}

// Keep the trusted environment layers when wrapping neutral I/O.
func (this *activityTerminal) ClientEnvironment() []string {
	if p, ok := this.Stream.(layeredSessionEnvironment); ok {
		return p.ClientEnvironment()
	}
	return this.Stream.Environ()
}
func (this *activityTerminal) AuthorizedKeyEnvironment() sys.EnvVars {
	if p, ok := this.Stream.(layeredSessionEnvironment); ok {
		return p.AuthorizedKeyEnvironment().Clone()
	}
	return nil
}
func (this *activityTerminal) OriginalCommand() (string, bool) {
	if p, ok := this.Stream.(sessionOriginalCommand); ok {
		return p.OriginalCommand()
	}
	return "", false
}

type activityTerminalStderr struct {
	terminal *activityTerminal
	stream   io.ReadWriter
}

func (this *activityTerminalStderr) Read(data []byte) (int, error) { return this.stream.Read(data) }
func (this *activityTerminalStderr) Write(data []byte) (int, error) {
	if err := this.terminal.connection.activity(); err != nil {
		return 0, err
	}
	return this.stream.Write(data)
}
