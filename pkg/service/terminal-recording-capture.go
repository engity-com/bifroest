package service

import (
	"io"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// recordedTerminal wraps only execution I/O, never an SSH Session. Both wrappers
// use terminalCapture's ordering, capture-before-delivery and fail-closed state.
type recordedTerminal struct {
	terminal.Stream
	*terminalCapture
	pty     terminal.Pty
	windows <-chan terminal.Window
	stderr  *recordedSessionStderr
}

func newRecordedTerminal(stream terminal.Stream, sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*recordedTerminal, error) {
	if isNilDependency(stream) {
		return nil, errors.System.Newf("nil execution stream for Recording")
	}
	pty, source, hasPty := stream.Pty()
	return newRecordedTerminalWithPty(stream, terminalRecordingPty{pty: pty, windows: source, hasPty: hasPty}, sink, elapsed, onFailure)
}

func newRecordedTerminalWithPty(stream terminal.Stream, snapshot terminalRecordingPty, sink recordingSink, elapsed func() time.Duration, onFailure func(error)) (*recordedTerminal, error) {
	pty, source, hasPty := snapshot.pty, snapshot.windows, snapshot.hasPty
	capture, err := newTerminalCapture(hasPty, pty.Window.Width, pty.Window.Height, sink, elapsed, onFailure)
	if err != nil {
		return nil, err
	}
	result := &recordedTerminal{Stream: stream, terminalCapture: capture, pty: terminal.ClonePty(pty)}
	result.stderr = &recordedSessionStderr{capture: capture, stream: stream.Stderr()}
	if hasPty && source != nil {
		target := make(chan terminal.Window, 1)
		target <- pty.Window
		result.windows = target
		go forwardCaptureWindows(capture, stream.Context(), source, target, pty.Window, func(value terminal.Window) terminal.Window { return value })
	} else {
		close(capture.done)
	}
	return result, nil
}
func (this *recordedTerminal) Write(data []byte) (int, error) {
	stream := recording.OutputStreamStdout
	if this.hasPty {
		stream = recording.OutputStreamTerminal
	}
	return this.write(this.Stream, stream, data)
}
func (this *recordedTerminal) Stderr() io.ReadWriter { return this.stderr }
func (this *recordedTerminal) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	return terminal.ClonePty(this.pty), this.windows, this.hasPty
}

func (this *recordedTerminal) ClientEnvironment() []string {
	if provider, ok := this.Stream.(layeredSessionEnvironment); ok {
		return append([]string(nil), provider.ClientEnvironment()...)
	}
	return append([]string(nil), this.Stream.Environ()...)
}
func (this *recordedTerminal) AuthorizedKeyEnvironment() sys.EnvVars {
	if provider, ok := this.Stream.(layeredSessionEnvironment); ok {
		return provider.AuthorizedKeyEnvironment().Clone()
	}
	return nil
}
func (this *recordedTerminal) OriginalCommand() (string, bool) {
	if provider, ok := this.Stream.(sessionOriginalCommand); ok {
		return provider.OriginalCommand()
	}
	return "", false
}
