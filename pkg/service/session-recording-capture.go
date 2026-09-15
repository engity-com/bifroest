package service

import (
	goerrors "errors"
	"io"
	"math"
	"reflect"
	"sync"
	"time"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/sys"
)

type recordingSink interface {
	WriteOutput(elapsed time.Duration, stream recording.OutputStream, data []byte) error
	WriteResize(elapsed time.Duration, columns, rows uint32) error
}

type recordedSession struct {
	essh.Session
	sink      recordingSink
	elapsed   func() time.Duration
	onFailure func(error)
	stderr    *recordedSessionStderr

	mu       sync.Mutex
	failure  error
	stopped  bool
	failed   chan struct{}
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	pty      essh.Pty
	windows  <-chan essh.Window
	hasPty   bool
	columns  uint32
	rows     uint32
}

type recordedSessionStderr struct {
	session *recordedSession
	stream  io.ReadWriter
}

type layeredSessionEnvironment interface {
	ClientEnvironment() []string
	AuthorizedKeyEnvironment() sys.EnvVars
}

type sessionOriginalCommand interface {
	OriginalCommand() (string, bool)
}

func newRecordedSession(session essh.Session, sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*recordedSession, error) {
	if isNilDependency(session) {
		return nil, errors.System.Newf("nil SSH session for Recording")
	}
	if isNilDependency(sink) {
		return nil, errors.System.Newf("nil Recording sink")
	}
	if elapsed == nil {
		return nil, errors.System.Newf("nil Recording elapsed-time function")
	}
	if onFailure == nil {
		return nil, errors.System.Newf("nil Recording failure callback")
	}

	pty, sourceWindows, hasPty := session.Pty()
	var columns, rows uint32
	if hasPty {
		var err error
		columns, err = initialWindowDimension(pty.Window.Width, "width")
		if err != nil {
			return nil, err
		}
		rows, err = initialWindowDimension(pty.Window.Height, "height")
		if err != nil {
			return nil, err
		}
	}
	result := &recordedSession{
		Session:   session,
		sink:      sink,
		elapsed:   elapsed,
		onFailure: onFailure,
		failed:    make(chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		pty:       clonePty(pty),
		hasPty:    hasPty,
		columns:   columns,
		rows:      rows,
	}
	result.stderr = &recordedSessionStderr{session: result, stream: session.Stderr()}
	if hasPty && sourceWindows != nil {
		windows := make(chan essh.Window, 1)
		windows <- pty.Window
		result.windows = windows
		go result.forwardWindows(sourceWindows, windows)
	} else {
		close(result.done)
	}
	return result, nil
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	default:
		return false
	}
}

func (this *recordedSession) Write(value []byte) (int, error) {
	stream := recording.OutputStreamStdout
	if this.hasPty {
		stream = recording.OutputStreamTerminal
	}
	return this.write(this.Session, stream, value)
}

func (this *recordedSession) Stderr() io.ReadWriter {
	return this.stderr
}

func (this *recordedSession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	return clonePty(this.pty), this.windows, this.hasPty
}

func (this *recordedSession) ClientEnvironment() []string {
	if provider, ok := this.Session.(layeredSessionEnvironment); ok {
		return append([]string(nil), provider.ClientEnvironment()...)
	}
	return append([]string(nil), this.Session.Environ()...)
}

func (this *recordedSession) AuthorizedKeyEnvironment() sys.EnvVars {
	if provider, ok := this.Session.(layeredSessionEnvironment); ok {
		return provider.AuthorizedKeyEnvironment().Clone()
	}
	return sys.EnvVars{}
}

func (this *recordedSession) OriginalCommand() (string, bool) {
	if provider, ok := this.Session.(sessionOriginalCommand); ok {
		return provider.OriginalCommand()
	}
	return "", false
}

func (this *recordedSession) write(target io.Writer, stream recording.OutputStream, value []byte) (int, error) {
	this.mu.Lock()
	if this.failure != nil {
		failure := this.failure
		this.mu.Unlock()
		return 0, failure
	}
	if this.stopped {
		this.mu.Unlock()
		return 0, errors.System.Newf("session Recording capture is stopped")
	}

	n, writeErr := target.Write(value)
	if n < 0 || n > len(value) {
		invalidCount := n
		if n < 0 {
			n = 0
		} else {
			n = len(value)
		}
		failure := this.poisonLocked("output", errors.System.Newf("SSH session writer returned invalid byte count %d for %d-byte write", invalidCount, len(value)))
		this.mu.Unlock()
		this.onFailure(failure)
		return n, goerrors.Join(writeErr, failure)
	}
	if n < len(value) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	if n <= 0 {
		this.mu.Unlock()
		return n, writeErr
	}
	recordErr := this.sink.WriteOutput(this.elapsed(), stream, value[:n])
	if recordErr == nil {
		this.mu.Unlock()
		return n, writeErr
	}
	failure := this.poisonLocked("output", recordErr)
	this.mu.Unlock()
	this.onFailure(failure)
	return n, goerrors.Join(writeErr, failure)
}

func (this *recordedSession) recordResize(window essh.Window) (error, bool) {
	this.mu.Lock()
	if this.failure != nil {
		failure := this.failure
		this.mu.Unlock()
		return failure, false
	}
	if this.stopped {
		this.mu.Unlock()
		return errors.System.Newf("session Recording capture is stopped"), false
	}
	columns, recordErr := effectiveWindowDimension(this.columns, window.Width, "width")
	var rows uint32
	if recordErr == nil {
		rows, recordErr = effectiveWindowDimension(this.rows, window.Height, "height")
	}
	if recordErr == nil && (columns == 0 || rows == 0) {
		recordErr = errors.System.Newf("effective terminal dimensions must be positive")
	}
	if recordErr == nil {
		recordErr = this.sink.WriteResize(this.elapsed(), columns, rows)
	}
	if recordErr == nil {
		this.columns = columns
		this.rows = rows
		this.mu.Unlock()
		return nil, false
	}
	failure := this.poisonLocked("resize", recordErr)
	this.mu.Unlock()
	return failure, true
}

func (this *recordedSession) stopAndWait() error {
	this.mu.Lock()
	this.stopped = true
	failure := this.failure
	this.mu.Unlock()
	this.stopOnce.Do(func() { close(this.stop) })
	<-this.done
	return failure
}

func initialWindowDimension(value int, name string) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, errors.System.Newf("invalid initial terminal %s %d", name, value)
	}
	return uint32(value), nil
}

func effectiveWindowDimension(current uint32, value int, name string) (uint32, error) {
	if value < 0 || uint64(value) > math.MaxUint32 {
		return 0, errors.System.Newf("invalid terminal %s %d", name, value)
	}
	if value == 0 {
		return current, nil
	}
	return uint32(value), nil
}

func (this *recordedSession) poisonLocked(event string, cause error) error {
	this.failure = errors.System.Newf("cannot record session %s: %w", event, cause)
	close(this.failed)
	return this.failure
}

func (this *recordedSession) forwardWindows(source <-chan essh.Window, target chan essh.Window) {
	var notifyFailure error
	defer func() {
		close(target)
		close(this.done)
		if notifyFailure != nil {
			this.onFailure(notifyFailure)
		}
	}()
	first := true
	for {
		select {
		case window, ok := <-source:
			if !ok {
				return
			}
			if first {
				first = false
				if window == this.pty.Window {
					continue
				}
			}
			if err, notify := this.recordResize(window); err != nil {
				if notify {
					notifyFailure = err
				}
				return
			}
			coalesceWindow(target, window)
		case <-this.Context().Done():
			return
		case <-this.failed:
			return
		case <-this.stop:
			return
		}
	}
}

func (this *recordedSessionStderr) Read(value []byte) (int, error) {
	return this.stream.Read(value)
}

func (this *recordedSessionStderr) Write(value []byte) (int, error) {
	stream := recording.OutputStreamStderr
	if this.session.hasPty {
		stream = recording.OutputStreamTerminal
	}
	return this.session.write(this.stream, stream, value)
}

func clonePty(value essh.Pty) essh.Pty {
	value.TerminalModes = cloneTerminalModes(value.TerminalModes)
	return value
}

func cloneTerminalModes(value map[uint8]uint32) map[uint8]uint32 {
	if value == nil {
		return nil
	}
	result := make(map[uint8]uint32, len(value))
	for mode, setting := range value {
		result[mode] = setting
	}
	return result
}

func coalesceWindow(target chan essh.Window, window essh.Window) {
	select {
	case target <- window:
		return
	default:
	}
	select {
	case <-target:
	default:
	}
	select {
	case target <- window:
	default:
	}
}
