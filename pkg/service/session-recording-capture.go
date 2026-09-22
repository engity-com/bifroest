package service

import (
	"bytes"
	goerrors "errors"
	"io"
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

	mu                              sync.Mutex
	failure                         error
	stopped                         bool
	failed                          chan struct{}
	stop                            chan struct{}
	done                            chan struct{}
	stopOnce                        sync.Once
	pty                             essh.Pty
	windows                         <-chan essh.Window
	hasPty                          bool
	columns                         uint32
	rows                            uint32
	terminalEndedWithCarriageReturn bool
}

type recordedSessionStderr struct {
	session *recordedSession
	stream  io.ReadWriter
}

type invalidSessionRecordingRequestError struct {
	cause error
}

func (this *invalidSessionRecordingRequestError) Error() string {
	return this.cause.Error()
}

func (this *invalidSessionRecordingRequestError) Unwrap() error {
	return this.cause
}

func invalidSessionRecordingRequest(err error) error {
	if err == nil {
		return nil
	}
	return &invalidSessionRecordingRequestError{cause: err}
}

func isInvalidSessionRecordingRequest(err error) bool {
	var target *invalidSessionRecordingRequestError
	return goerrors.As(err, &target)
}

type layeredSessionEnvironment interface {
	ClientEnvironment() []string
	AuthorizedKeyEnvironment() sys.EnvVars
}

type sessionOriginalCommand interface {
	OriginalCommand() (string, bool)
}

type recordedSessionPty struct {
	pty     essh.Pty
	windows <-chan essh.Window
	hasPty  bool
}

func newRecordedSession(session essh.Session, sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*recordedSession, error) {
	if isNilDependency(session) {
		return nil, errors.System.Newf("nil SSH session for Recording")
	}
	pty, windows, hasPty := session.Pty()
	return newRecordedSessionWithPty(session, recordedSessionPty{pty: pty, windows: windows, hasPty: hasPty}, sink, elapsed, onFailure)
}

func newRecordedSessionWithPty(session essh.Session, snapshot recordedSessionPty, sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*recordedSession, error) {
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

	var columns, rows uint32
	if snapshot.hasPty {
		var err error
		columns, err = initialWindowDimension(snapshot.pty.Window.Width, "width")
		if err != nil {
			return nil, err
		}
		rows, err = initialWindowDimension(snapshot.pty.Window.Height, "height")
		if err != nil {
			return nil, err
		}
	}
	if columns == 0 {
		columns = defaultSessionRecordingColumns
	}
	if rows == 0 {
		rows = defaultSessionRecordingRows
	}
	result := &recordedSession{
		Session:   session,
		sink:      sink,
		elapsed:   elapsed,
		onFailure: onFailure,
		failed:    make(chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		pty:       clonePty(snapshot.pty),
		hasPty:    snapshot.hasPty,
		columns:   columns,
		rows:      rows,
	}
	result.stderr = &recordedSessionStderr{session: result, stream: session.Stderr()}
	if snapshot.hasPty && snapshot.windows != nil {
		windows := make(chan essh.Window, 1)
		windows <- snapshot.pty.Window
		result.windows = windows
		go result.forwardWindows(snapshot.windows, windows)
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
	normalizeTerminal := false
	if this.hasPty {
		stream = recording.OutputStreamTerminal
		normalizeTerminal = true
	}
	return this.write(this.Session, stream, normalizeTerminal, value)
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

func (this *recordedSession) write(target io.Writer, stream recording.OutputStream, normalizeTerminal bool, value []byte) (int, error) {
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

	if len(value) == 0 {
		n, writeErr := target.Write(value)
		if n == 0 {
			this.mu.Unlock()
			return 0, writeErr
		}
		invalidCountErr := errors.System.Newf("SSH session writer returned invalid byte count %d for empty write", n)
		failure := this.poisonLocked("output delivery", goerrors.Join(writeErr, invalidCountErr))
		this.mu.Unlock()
		this.onFailure(failure)
		return 0, goerrors.Join(writeErr, failure)
	}

	recorded := value
	if normalizeTerminal {
		recorded = normalizeSessionTerminalOutput(recorded, this.terminalEndedWithCarriageReturn)
	}
	if recordErr := this.sink.WriteOutput(this.elapsed(), stream, recorded); recordErr != nil {
		failure := this.poisonLocked("output", recordErr)
		this.mu.Unlock()
		this.onFailure(failure)
		return 0, failure
	}
	if stream == recording.OutputStreamTerminal {
		this.terminalEndedWithCarriageReturn = recorded[len(recorded)-1] == '\r'
	}

	n, writeErr := target.Write(value)
	if n < 0 || n > len(value) {
		invalidCount := n
		if n < 0 {
			n = 0
		} else {
			n = len(value)
		}
		invalidCountErr := errors.System.Newf("SSH session writer returned invalid byte count %d for %d-byte write", invalidCount, len(value))
		failure := this.poisonLocked("output delivery", goerrors.Join(writeErr, invalidCountErr))
		this.mu.Unlock()
		this.onFailure(failure)
		return n, goerrors.Join(writeErr, failure)
	}
	if n == len(value) {
		this.mu.Unlock()
		return n, writeErr
	}
	if writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	failure := this.poisonLocked("output delivery", errors.System.Newf("SSH session writer accepted %d of %d recorded bytes: %w", n, len(value), writeErr))
	this.mu.Unlock()
	this.onFailure(failure)
	return n, failure
}

func normalizeSessionTerminalOutput(value []byte, precededByCarriageReturn bool) []byte {
	normalized := bytes.ReplaceAll(value, []byte{'\n'}, []byte{'\r', '\n'})
	normalized = bytes.ReplaceAll(normalized, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'})
	if precededByCarriageReturn && value[0] == '\n' {
		return normalized[1:]
	}
	return normalized
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
	invalidRequest := recordErr != nil
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
	if invalidRequest {
		recordErr = invalidSessionRecordingRequest(recordErr)
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
	if value < 0 || uint64(value) > uint64(recording.MaximumCastTerminalDimension) {
		return 0, errors.System.Newf("invalid initial terminal %s %d", name, value)
	}
	return uint32(value), nil
}

func effectiveWindowDimension(current uint32, value int, name string) (uint32, error) {
	if value < 0 || uint64(value) > uint64(recording.MaximumCastTerminalDimension) {
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
	return this.session.write(this.stream, stream, false, value)
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
