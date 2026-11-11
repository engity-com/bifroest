package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// No embedded SSH session/context: this implements exactly execution I/O.
type recordingTerminalTestStream struct {
	ctx            context.Context
	cancel         context.CancelFunc
	stdin          bytes.Reader
	stdout, stderr bytes.Buffer
	pty            terminal.Pty
	hasPty         bool
	windows        chan terminal.Window
	ptyCalls       atomic.Int32
	signals        chan<- terminal.Signal
}

func (this *recordingTerminalTestStream) Context() context.Context { return this.ctx }
func (this *recordingTerminalTestStream) Read(value []byte) (int, error) {
	return this.stdin.Read(value)
}
func (this *recordingTerminalTestStream) Write(value []byte) (int, error) {
	return this.stdout.Write(value)
}
func (this *recordingTerminalTestStream) Stderr() io.ReadWriter { return &this.stderr }
func (*recordingTerminalTestStream) RawCommand() string         { return "command" }
func (*recordingTerminalTestStream) Environ() []string          { return []string{"CLIENT=value"} }
func (this *recordingTerminalTestStream) Close() error          { this.cancel(); return nil }
func (*recordingTerminalTestStream) CloseWrite() error          { return nil }
func (this *recordingTerminalTestStream) Signals(receiver chan<- terminal.Signal) {
	this.signals = receiver
}
func (this *recordingTerminalTestStream) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	this.ptyCalls.Add(1)
	return terminal.ClonePty(this.pty), this.windows, this.hasPty
}
func newRecordingTerminalTestStream(t *testing.T) *recordingTerminalTestStream {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &recordingTerminalTestStream{ctx: ctx, cancel: cancel, windows: make(chan terminal.Window, 8)}
}

func TestNeutralRecordingUsesSharedCaptureAndDelegatesExecutionIo(t *testing.T) {
	source := newRecordingTerminalTestStream(t)
	source.stdin = *bytes.NewReader([]byte("input"))
	sink := &captureTestSink{}
	capture, err := newRecordedTerminal(source, sink, func() time.Duration { return time.Millisecond }, func(error) { t.Error("unexpected failure") })
	require.NoError(t, err)
	defer func() { require.NoError(t, capture.stopAndWait()) }()
	data, err := io.ReadAll(capture)
	require.NoError(t, err)
	require.Equal(t, "input", string(data))
	_, err = io.WriteString(capture, "stdout\n")
	require.NoError(t, err)
	_, err = io.WriteString(capture.Stderr(), "stderr\n")
	require.NoError(t, err)
	require.Equal(t, []captureTestOutput{{elapsed: time.Millisecond, stream: recording.OutputStreamStdout, data: []byte("stdout\n")}, {elapsed: time.Millisecond, stream: recording.OutputStreamStderr, data: []byte("stderr\n")}}, sink.outputEvents())
	require.Equal(t, "stdout\n", source.stdout.String())
	require.Equal(t, "stderr\n", source.stderr.String())
	require.Equal(t, "command", capture.RawCommand())
	require.Equal(t, []string{"CLIENT=value"}, capture.ClientEnvironment())
	channels := make(chan terminal.Signal, 1)
	capture.Signals(channels)
	require.Equal(t, (chan<- terminal.Signal)(channels), source.signals)
	require.NoError(t, capture.CloseWrite())
	require.NoError(t, capture.Close())
	require.ErrorIs(t, capture.Context().Err(), context.Canceled)
	require.EqualValues(t, 1, source.ptyCalls.Load())
}

func TestNeutralRecordingSnapshotsAndRecordsEveryResizeBeforeCoalescing(t *testing.T) {
	source := newRecordingTerminalTestStream(t)
	source.hasPty = true
	source.pty = terminal.Pty{Term: "xterm", Window: terminal.Window{Width: 80, Height: 24}, TerminalModes: map[uint8]uint32{53: 1}}
	sink := &captureTestSink{}
	capture, err := newRecordedTerminal(source, sink, func() time.Duration { return time.Millisecond }, func(error) { t.Error("unexpected failure") })
	require.NoError(t, err)
	defer func() { require.NoError(t, capture.stopAndWait()) }()
	snapshot, windows, ok := capture.Pty()
	require.True(t, ok)
	snapshot.TerminalModes[53] = 2
	second, secondWindows, _ := capture.Pty()
	require.Equal(t, uint32(1), second.TerminalModes[53])
	require.Equal(t, windows, secondWindows)
	source.windows <- source.pty.Window // Initial duplicates do not create resize events.
	source.windows <- terminal.Window{Width: 81, Height: 25}
	source.windows <- terminal.Window{Width: 82, Height: 26}
	source.windows <- terminal.Window{Width: 83, Height: 27}
	close(source.windows)
	select {
	case <-capture.done:
	case <-time.After(time.Second):
		t.Fatal("resize capture did not drain")
	}
	require.Eventually(t, func() bool { return len(sink.resizeEvents()) == 3 }, time.Second, time.Millisecond)
	require.Equal(t, terminal.Window{Width: 83, Height: 27}, <-windows)
	_, err = io.WriteString(capture, "first\r")
	require.NoError(t, err)
	_, err = io.WriteString(capture.Stderr(), "\nsecond\n")
	require.NoError(t, err)
	events := sink.outputEvents()
	require.Len(t, events, 2)
	require.Equal(t, recording.OutputStreamTerminal, events[0].stream)
	require.Equal(t, []byte("\nsecond\r\n"), events[1].data)
	require.NoError(t, capture.stopAndWait())
	_, err = capture.Write([]byte("after stop"))
	require.ErrorContains(t, err, "capture is stopped")
}

func TestNeutralRecordingFailureClosesExecutionBeforeDelivery(t *testing.T) {
	source := newRecordingTerminalTestStream(t)
	cause := errors.New("spool failed")
	sink := &captureTestSink{outputErr: cause}
	failures := 0
	capture, err := newRecordedTerminal(source, sink, func() time.Duration { return 0 }, func(error) { failures++; _ = source.Close() })
	require.NoError(t, err)
	_, err = capture.Write([]byte("not delivered"))
	require.ErrorIs(t, err, cause)
	require.Empty(t, source.stdout.String())
	require.ErrorIs(t, source.Context().Err(), context.Canceled)
	_, err = capture.Stderr().Write([]byte("also blocked"))
	require.ErrorIs(t, err, cause)
	require.Equal(t, 1, failures)
	require.ErrorIs(t, capture.stopAndWait(), cause)
}

var _ terminal.Stream = (*recordedTerminal)(nil)
var _ terminal.Stream = (*recordingTerminalTestStream)(nil)
