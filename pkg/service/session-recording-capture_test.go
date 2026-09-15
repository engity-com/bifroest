package service

import (
	"bytes"
	"context"
	goerrors "errors"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	_ essh.Session  = (*recordedSession)(nil)
	_ recordingSink = (*recording.ActiveCastZstd)(nil)
	_ recordingSink = (*recording.ActiveBECast)(nil)
)

func TestRecordedSessionRejectsNilDependencies(t *testing.T) {
	session := newCaptureTestSession(t.Context())
	sink := &captureTestSink{}
	var typedNilSession *captureTestSession
	var typedNilSink *captureTestSink
	elapsed := func() time.Duration { return 0 }
	onFailure := func(error) {}

	tests := []struct {
		name      string
		session   essh.Session
		sink      recordingSink
		elapsed   func() time.Duration
		onFailure func(error)
	}{
		{name: "session", sink: sink, elapsed: elapsed, onFailure: onFailure},
		{name: "typed nil session", session: typedNilSession, sink: sink, elapsed: elapsed, onFailure: onFailure},
		{name: "sink", session: session, elapsed: elapsed, onFailure: onFailure},
		{name: "typed nil sink", session: session, sink: typedNilSink, elapsed: elapsed, onFailure: onFailure},
		{name: "elapsed", session: session, sink: sink, onFailure: onFailure},
		{name: "failure callback", session: session, sink: sink, elapsed: elapsed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			captured, err := newRecordedSession(test.session, test.sink, test.elapsed, test.onFailure)
			require.Nil(t, captured)
			require.Error(t, err)
			require.True(t, bferrors.System.IsErr(err))
		})
	}
}

func TestRecordedSessionRejectsInvalidInitialPtyDimensions(t *testing.T) {
	tests := []struct {
		name   string
		window essh.Window
	}{
		{name: "negative width", window: essh.Window{Width: -1, Height: 24}},
		{name: "negative height", window: essh.Window{Width: 80, Height: -1}},
	}
	if strconv.IntSize > 32 {
		tooLarge := uint64(math.MaxUint32) + 1
		tests = append(tests, struct {
			name   string
			window essh.Window
		}{name: "width exceeds uint32", window: essh.Window{Width: int(tooLarge), Height: 24}})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newCaptureTestSession(t.Context())
			session.hasPty = true
			session.pty.Window = test.window

			wrapper, err := newRecordedSession(session, &captureTestSink{}, func() time.Duration { return 0 }, func(error) {})

			require.Nil(t, wrapper)
			require.ErrorContains(t, err, "invalid initial terminal")
			require.True(t, bferrors.IsType(err, bferrors.System))
		})
	}
}

func TestRecordedSessionDelegatesSessionAndChannel(t *testing.T) {
	ctx := newCaptureTestContext(t.Context())
	session := newCaptureTestSession(ctx)
	session.user = "alice"
	session.remoteAddr = captureTestAddr("remote")
	session.localAddr = captureTestAddr("local")
	session.environment = []string{"ONE=1", "TWO=2"}
	session.command = []string{"printf", "hello"}
	session.rawCommand = "printf hello"
	session.subsystem = "test-subsystem"
	session.permissions = essh.Permissions{Permissions: &gossh.Permissions{Extensions: map[string]string{"role": "test"}}}
	session.stdin.reader.WriteString("stdin")
	session.stderr.reader.WriteString("stderr input")
	sink := &captureTestSink{}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})

	stdin := make([]byte, 5)
	n, err := wrapper.Read(stdin)
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "stdin", string(stdin))
	require.Equal(t, session.user, wrapper.User())
	require.Equal(t, session.remoteAddr, wrapper.RemoteAddr())
	require.Equal(t, session.localAddr, wrapper.LocalAddr())
	require.Equal(t, session.environment, wrapper.Environ())
	require.Equal(t, session.command, wrapper.Command())
	require.Equal(t, session.rawCommand, wrapper.RawCommand())
	require.Equal(t, session.subsystem, wrapper.Subsystem())
	require.Nil(t, wrapper.PublicKey())
	require.Same(t, ctx, wrapper.Context())
	require.Equal(t, session.permissions, wrapper.Permissions())

	require.NoError(t, wrapper.Exit(23))
	require.Equal(t, 23, session.exitCode)
	signals := make(chan essh.Signal, 1)
	breaks := make(chan bool, 1)
	wrapper.Signals(signals)
	wrapper.Break(breaks)
	require.Equal(t, (chan<- essh.Signal)(signals), session.signals)
	require.Equal(t, (chan<- bool)(breaks), session.breaks)

	accepted, err := wrapper.SendRequest("request", true, []byte("payload"))
	require.NoError(t, err)
	require.True(t, accepted)
	require.Equal(t, captureTestRequest{name: "request", wantReply: true, payload: []byte("payload")}, session.request)
	require.NoError(t, wrapper.CloseWrite())
	require.Equal(t, int32(1), session.closeWriteCalls.Load())
	require.NoError(t, wrapper.Close())
	require.Equal(t, int32(1), session.closeCalls.Load())

	stderr := wrapper.Stderr()
	require.Same(t, stderr, wrapper.Stderr())
	stderrInput := make([]byte, len("stderr input"))
	n, err = stderr.Read(stderrInput)
	require.NoError(t, err)
	require.Equal(t, len(stderrInput), n)
	require.Equal(t, "stderr input", string(stderrInput))
	require.Empty(t, sink.outputEvents())
	require.Empty(t, sink.resizeEvents())
	require.Equal(t, int32(1), session.ptyCalls.Load())
}

func TestRecordedSessionCapturesOutputStreamsAndSuccessfulBytes(t *testing.T) {
	t.Run("non PTY", func(t *testing.T) {
		session := newCaptureTestSession(t.Context())
		sink := &captureTestSink{}
		wrapper := requireRecordedSession(t, session, sink, func(error) {})

		n, err := wrapper.Write([]byte("stdout"))
		require.NoError(t, err)
		require.Equal(t, 6, n)
		n, err = wrapper.Stderr().Write([]byte("stderr"))
		require.NoError(t, err)
		require.Equal(t, 6, n)
		require.Equal(t, []captureTestOutput{
			{elapsed: time.Millisecond, stream: recording.OutputStreamStdout, data: []byte("stdout")},
			{elapsed: 2 * time.Millisecond, stream: recording.OutputStreamStderr, data: []byte("stderr")},
		}, sink.outputEvents())
	})

	t.Run("PTY", func(t *testing.T) {
		session := newCaptureTestSession(t.Context())
		session.hasPty = true
		sink := &captureTestSink{}
		wrapper := requireRecordedSession(t, session, sink, func(error) {})

		_, err := wrapper.Write([]byte("stdout"))
		require.NoError(t, err)
		_, err = wrapper.Stderr().Write([]byte("stderr"))
		require.NoError(t, err)
		events := sink.outputEvents()
		require.Len(t, events, 2)
		require.Equal(t, recording.OutputStreamTerminal, events[0].stream)
		require.Equal(t, recording.OutputStreamTerminal, events[1].stream)
	})

	t.Run("partial transport write", func(t *testing.T) {
		transportCause := goerrors.New("transport write failed")
		session := newCaptureTestSession(t.Context())
		session.stdout.write = func(value []byte) (int, error) {
			_, _ = session.stdout.writer.Write(value[:3])
			return 3, transportCause
		}
		sink := &captureTestSink{}
		wrapper := requireRecordedSession(t, session, sink, func(error) {})

		n, err := wrapper.Write([]byte("partial"))
		require.Equal(t, 3, n)
		require.ErrorIs(t, err, transportCause)
		require.Equal(t, []byte("par"), sink.outputEvents()[0].data)
	})

	t.Run("partial stderr transport write", func(t *testing.T) {
		transportCause := goerrors.New("stderr transport write failed")
		session := newCaptureTestSession(t.Context())
		session.stderr.write = func(value []byte) (int, error) {
			_, _ = session.stderr.writer.Write(value[:4])
			return 4, transportCause
		}
		sink := &captureTestSink{}
		wrapper := requireRecordedSession(t, session, sink, func(error) {})

		n, err := wrapper.Stderr().Write([]byte("partial"))
		require.Equal(t, 4, n)
		require.ErrorIs(t, err, transportCause)
		events := sink.outputEvents()
		require.Len(t, events, 1)
		require.Equal(t, recording.OutputStreamStderr, events[0].stream)
		require.Equal(t, []byte("part"), events[0].data)
	})

	t.Run("short write without transport error", func(t *testing.T) {
		session := newCaptureTestSession(t.Context())
		session.stdout.write = func([]byte) (int, error) { return 2, nil }
		sink := &captureTestSink{}
		wrapper := requireRecordedSession(t, session, sink, func(error) {})

		n, err := wrapper.Write([]byte("short"))
		require.Equal(t, 2, n)
		require.ErrorIs(t, err, io.ErrShortWrite)
		require.Equal(t, []byte("sh"), sink.outputEvents()[0].data)
	})

	t.Run("invalid transport byte counts", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			transportN int
			expectedN  int
		}{
			{name: "negative", transportN: -1, expectedN: 0},
			{name: "too large", transportN: 6, expectedN: 5},
		} {
			t.Run(test.name, func(t *testing.T) {
				session := newCaptureTestSession(t.Context())
				session.stdout.write = func([]byte) (int, error) { return test.transportN, nil }
				sink := &captureTestSink{}
				var callbackCalls atomic.Int32
				var failure error
				wrapper := requireRecordedSession(t, session, sink, func(err error) {
					callbackCalls.Add(1)
					failure = err
				})

				n, err := wrapper.Write([]byte("value"))
				require.Equal(t, test.expectedN, n)
				require.True(t, bferrors.System.IsErr(err))
				require.Empty(t, sink.outputEvents())
				require.Equal(t, int32(1), callbackCalls.Load())
				n, blockedErr := wrapper.Write([]byte("blocked"))
				require.Zero(t, n)
				require.ErrorIs(t, err, failure)
				require.Same(t, failure, blockedErr)
			})
		}
	})
}

func TestRecordedSessionRecordingFailurePoisonsOutput(t *testing.T) {
	transportCause := goerrors.New("transport failed after bytes")
	recordCause := bferrors.Config.Newf("recording storage rejected output")
	session := newCaptureTestSession(t.Context())
	session.stdout.write = func(value []byte) (int, error) {
		_, _ = session.stdout.writer.Write(value[:2])
		return 2, transportCause
	}
	sink := &captureTestSink{outputErr: recordCause}
	var callbackCalls atomic.Int32
	var callbackErr error
	var wrapper *recordedSession
	callbackReentry := make(chan error, 1)
	wrapper, err := newRecordedSession(session, sink, func() time.Duration { return time.Second }, func(err error) {
		callbackCalls.Add(1)
		callbackErr = err
		_, reentryErr := wrapper.Write([]byte("reentrant"))
		callbackReentry <- reentryErr
	})
	require.NoError(t, err)

	n, err := wrapper.Write([]byte("first"))
	require.Equal(t, 2, n)
	require.ErrorIs(t, err, transportCause)
	require.ErrorIs(t, err, recordCause)
	require.True(t, bferrors.Config.IsErr(err))
	require.Equal(t, int32(1), callbackCalls.Load())
	require.ErrorIs(t, <-callbackReentry, callbackErr)
	require.True(t, bferrors.Config.IsErr(callbackErr))

	n, err = wrapper.Stderr().Write([]byte("blocked stderr"))
	require.Zero(t, n)
	require.Same(t, callbackErr, err)
	n, err = wrapper.Write([]byte("blocked stdout"))
	require.Zero(t, n)
	require.Same(t, callbackErr, err)
	require.Equal(t, int32(1), session.stdout.writeCalls.Load())
	require.Zero(t, session.stderr.writeCalls.Load())
	require.Equal(t, int32(1), callbackCalls.Load())
}

func TestRecordedSessionSerializesStdoutAndStderrOrder(t *testing.T) {
	session := newCaptureTestSession(t.Context())
	stdoutEntered := make(chan struct{})
	releaseStdout := make(chan struct{})
	session.stdout.write = func(value []byte) (int, error) {
		close(stdoutEntered)
		<-releaseStdout
		return session.stdout.writer.Write(value)
	}
	sink := &captureTestSink{}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([]byte("stdout"))
		stdoutDone <- err
	}()
	<-stdoutEntered
	go func() {
		_, err := wrapper.Stderr().Write([]byte("stderr"))
		stderrDone <- err
	}()
	close(releaseStdout)
	require.NoError(t, <-stdoutDone)
	require.NoError(t, <-stderrDone)

	events := sink.outputEvents()
	require.Len(t, events, 2)
	require.Equal(t, recording.OutputStreamStdout, events[0].stream)
	require.Equal(t, recording.OutputStreamStderr, events[1].stream)
}

func TestRecordedSessionSerializesOutputAndResizeOrder(t *testing.T) {
	initial := essh.Window{Width: 80, Height: 24}
	resized := essh.Window{Width: 100, Height: 30}
	source := make(chan essh.Window, 2)
	source <- initial
	session := newCaptureTestSession(t.Context())
	session.hasPty = true
	session.pty.Window = initial
	session.windows = source
	stdoutEntered := make(chan struct{})
	releaseStdout := make(chan struct{})
	session.stdout.write = func(value []byte) (int, error) {
		close(stdoutEntered)
		<-releaseStdout
		return session.stdout.writer.Write(value)
	}
	sink := &captureTestSink{}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})
	_, windows, _ := wrapper.Pty()
	require.Equal(t, initial, <-windows)

	stdoutDone := make(chan error, 1)
	go func() {
		_, err := wrapper.Write([]byte("output"))
		stdoutDone <- err
	}()
	<-stdoutEntered
	source <- resized
	close(releaseStdout)
	require.NoError(t, <-stdoutDone)
	waitForCaptureChanges(t, sink, 1)
	require.Equal(t, []string{"output", "resize"}, sink.eventOrder())
	require.Equal(t, resized, <-windows)
	close(source)
}

func TestRecordedSessionPtySnapshotsAndResizeCapture(t *testing.T) {
	ctx := newCaptureTestContext(t.Context())
	initial := essh.Window{Width: 80, Height: 24, WidthPixels: 800, HeightPixels: 600}
	source := make(chan essh.Window, 4)
	source <- initial
	session := newCaptureTestSession(ctx)
	session.hasPty = true
	session.pty = essh.Pty{Term: "xterm", Window: initial, TerminalModes: gossh.TerminalModes{gossh.ECHO: 1}}
	session.windows = source
	sink := &captureTestSink{changed: make(chan struct{}, 8)}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})

	pty, windows, ok := wrapper.Pty()
	require.True(t, ok)
	require.Equal(t, "xterm", pty.Term)
	require.Equal(t, uint32(1), pty.TerminalModes[gossh.ECHO])
	pty.TerminalModes[gossh.ECHO] = 0
	session.pty.TerminalModes[gossh.ECHO] = 2
	secondPty, secondWindows, secondOK := wrapper.Pty()
	require.True(t, secondOK)
	require.Equal(t, windows, secondWindows)
	require.Equal(t, uint32(1), secondPty.TerminalModes[gossh.ECHO])
	require.Equal(t, initial, <-windows)
	require.Never(t, func() bool { return len(sink.resizeEvents()) != 0 }, 20*time.Millisecond, time.Millisecond)

	first := essh.Window{Width: 100, Height: 30, WidthPixels: 1000, HeightPixels: 750}
	second := essh.Window{Width: 132, Height: 43, WidthPixels: 1320, HeightPixels: 860}
	source <- first
	waitForCaptureChanges(t, sink, 1)
	require.Equal(t, first, <-windows)
	source <- second
	waitForCaptureChanges(t, sink, 2)
	require.Equal(t, second, <-windows)
	require.Equal(t, []captureTestResize{
		{elapsed: time.Millisecond, columns: 100, rows: 30},
		{elapsed: 2 * time.Millisecond, columns: 132, rows: 43},
	}, sink.resizeEvents())

	close(source)
	_, open := <-windows
	require.False(t, open)
}

func TestRecordedSessionForwardsAndRecordsFirstDifferentWindow(t *testing.T) {
	initial := essh.Window{Width: 80, Height: 24}
	latest := essh.Window{Width: 120, Height: 40}
	source := make(chan essh.Window, 1)
	session := newCaptureTestSession(t.Context())
	session.hasPty = true
	session.pty.Window = initial
	session.windows = source
	sink := &captureTestSink{changed: make(chan struct{}, 1)}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})
	_, windows, _ := wrapper.Pty()

	require.Equal(t, initial, <-windows)
	source <- latest
	waitForCaptureChanges(t, sink, 1)
	require.Equal(t, latest, <-windows)
	require.Equal(t, []captureTestResize{{elapsed: time.Millisecond, columns: 120, rows: 40}}, sink.resizeEvents())
	close(source)
}

func TestRecordedSessionUsesEffectiveResizeDimensions(t *testing.T) {
	initial := essh.Window{Width: 80, Height: 24}
	source := make(chan essh.Window, 1)
	session := newCaptureTestSession(t.Context())
	session.hasPty = true
	session.pty.Window = initial
	session.windows = source
	sink := &captureTestSink{changed: make(chan struct{}, 3)}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})
	_, windows, _ := wrapper.Pty()
	require.Equal(t, initial, <-windows)

	changes := []essh.Window{
		{Width: 0, Height: 40},
		{Width: 120, Height: 0},
		{},
	}
	for index, window := range changes {
		source <- window
		waitForCaptureChanges(t, sink, index+1)
		require.Equal(t, window, <-windows)
	}
	require.Equal(t, []captureTestResize{
		{elapsed: time.Millisecond, columns: 80, rows: 40},
		{elapsed: 2 * time.Millisecond, columns: 120, rows: 40},
		{elapsed: 3 * time.Millisecond, columns: 120, rows: 40},
	}, sink.resizeEvents())
	close(source)
}

func TestRecordedSessionRejectsInvalidWindowDimensions(t *testing.T) {
	tests := []struct {
		name   string
		window essh.Window
	}{
		{name: "negative width", window: essh.Window{Width: -1, Height: 24}},
		{name: "negative height", window: essh.Window{Width: 80, Height: -1}},
	}
	if strconv.IntSize > 32 {
		tooLarge := uint64(math.MaxUint32) + 1
		tests = append(tests, struct {
			name   string
			window essh.Window
		}{name: "width exceeds uint32", window: essh.Window{Width: int(tooLarge), Height: 24}})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initial := essh.Window{Width: 80, Height: 24}
			source := make(chan essh.Window, 1)
			session := newCaptureTestSession(t.Context())
			session.hasPty = true
			session.pty.Window = initial
			session.windows = source
			sink := &captureTestSink{}
			callback := make(chan error, 1)
			wrapper := requireRecordedSession(t, session, sink, func(err error) { callback <- err })
			_, windows, _ := wrapper.Pty()
			require.Equal(t, initial, <-windows)

			source <- test.window
			failure := <-callback
			require.ErrorContains(t, failure, "invalid terminal")
			require.Empty(t, sink.resizeEvents())
			requireChannelClosed(t, windows)
		})
	}
}

func TestCoalesceWindowReplacesPendingValue(t *testing.T) {
	target := make(chan essh.Window, 1)
	first := essh.Window{Width: 80, Height: 24}
	latest := essh.Window{Width: 120, Height: 40}
	target <- first

	coalesceWindow(target, latest)

	require.Equal(t, latest, <-target)
}

func TestRecordedSessionPtyProxyClosesWithContextAndSource(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		plain, cancel := context.WithCancel(t.Context())
		ctx := newCaptureTestContext(plain)
		source := make(chan essh.Window)
		session := newCaptureTestSession(ctx)
		session.hasPty = true
		session.windows = source
		wrapper := requireRecordedSession(t, session, &captureTestSink{}, func(error) {})
		_, windows, _ := wrapper.Pty()
		require.Equal(t, essh.Window{}, <-windows)
		cancel()
		requireChannelClosed(t, windows)
	})

	t.Run("source", func(t *testing.T) {
		source := make(chan essh.Window)
		session := newCaptureTestSession(t.Context())
		session.hasPty = true
		session.windows = source
		wrapper := requireRecordedSession(t, session, &captureTestSink{}, func(error) {})
		_, windows, _ := wrapper.Pty()
		require.Equal(t, essh.Window{}, <-windows)
		close(source)
		requireChannelClosed(t, windows)
	})

	t.Run("no proxy without a window source", func(t *testing.T) {
		session := newCaptureTestSession(t.Context())
		session.hasPty = true
		wrapper := requireRecordedSession(t, session, &captureTestSink{}, func(error) {})
		_, windows, ok := wrapper.Pty()
		require.True(t, ok)
		require.Nil(t, windows)
	})

	t.Run("no proxy without an accepted PTY", func(t *testing.T) {
		source := make(chan essh.Window, 1)
		source <- essh.Window{Width: 80, Height: 24}
		session := newCaptureTestSession(t.Context())
		session.windows = source
		wrapper := requireRecordedSession(t, session, &captureTestSink{}, func(error) {})
		_, windows, ok := wrapper.Pty()
		require.False(t, ok)
		require.Nil(t, windows)
		require.Len(t, source, 1, "a non-PTY source must not be consumed")
	})
}

func TestRecordedSessionResizeFailurePoisonsSession(t *testing.T) {
	initial := essh.Window{Width: 80, Height: 24}
	source := make(chan essh.Window, 2)
	source <- initial
	source <- essh.Window{Width: 100, Height: 30}
	session := newCaptureTestSession(t.Context())
	session.hasPty = true
	session.pty.Window = initial
	session.windows = source
	recordCause := bferrors.System.Newf("resize storage failed")
	sink := &captureTestSink{resizeErr: recordCause, changed: make(chan struct{}, 1)}
	callback := make(chan error, 1)
	wrapper := requireRecordedSession(t, session, sink, func(err error) { callback <- err })
	_, windows, _ := wrapper.Pty()
	require.Equal(t, initial, <-windows)

	failure := <-callback
	require.ErrorIs(t, failure, recordCause)
	requireChannelClosed(t, windows)
	n, err := wrapper.Write([]byte("blocked"))
	require.Zero(t, n)
	require.Same(t, failure, err)
	require.Zero(t, session.stdout.writeCalls.Load())
	select {
	case unexpected := <-callback:
		t.Fatalf("failure callback invoked more than once: %v", unexpected)
	default:
	}
}

func TestRecordedSessionOutputFailureClosesPtyProxy(t *testing.T) {
	source := make(chan essh.Window)
	session := newCaptureTestSession(t.Context())
	session.hasPty = true
	session.windows = source
	sink := &captureTestSink{outputErr: bferrors.System.Newf("output storage failed")}
	wrapper := requireRecordedSession(t, session, sink, func(error) {})
	_, windows, _ := wrapper.Pty()
	require.Equal(t, essh.Window{}, <-windows)

	_, err := wrapper.Write([]byte("poison"))
	require.Error(t, err)
	requireChannelClosed(t, windows)
}

func TestRecordedSessionPreservesOptionalEnvironmentSemantics(t *testing.T) {
	t.Run("authorized key session", func(t *testing.T) {
		base := newCaptureTestSession(t.Context())
		layered := &authorizedKeySession{
			Session:                  base,
			clientEnvironment:        []string{"CLIENT=value"},
			authorizedKeyEnvironment: sys.EnvVars{"FROM_KEY": "value"},
			originalCommand:          "original command",
			hasOriginalCommand:       true,
		}
		wrapper := requireRecordedSession(t, layered, &captureTestSink{}, func(error) {})

		client := wrapper.ClientEnvironment()
		authorized := wrapper.AuthorizedKeyEnvironment()
		original, present := wrapper.OriginalCommand()
		require.Equal(t, []string{"CLIENT=value"}, client)
		require.Equal(t, sys.EnvVars{"FROM_KEY": "value"}, authorized)
		require.Equal(t, "original command", original)
		require.True(t, present)

		client[0] = "CHANGED=value"
		authorized["FROM_KEY"] = "changed"
		require.Equal(t, []string{"CLIENT=value"}, wrapper.ClientEnvironment())
		require.Equal(t, sys.EnvVars{"FROM_KEY": "value"}, wrapper.AuthorizedKeyEnvironment())
	})

	t.Run("fallback", func(t *testing.T) {
		base := newCaptureTestSession(t.Context())
		base.environment = []string{"CLIENT=value"}
		wrapper := requireRecordedSession(t, base, &captureTestSink{}, func(error) {})

		client := wrapper.ClientEnvironment()
		client[0] = "CHANGED=value"
		require.Equal(t, []string{"CLIENT=value"}, wrapper.ClientEnvironment())
		authorized := wrapper.AuthorizedKeyEnvironment()
		authorized["CHANGED"] = "value"
		require.Empty(t, wrapper.AuthorizedKeyEnvironment())
		original, present := wrapper.OriginalCommand()
		require.Empty(t, original)
		require.False(t, present)
	})
}

func requireRecordedSession(t *testing.T, session essh.Session, sink recordingSink, onFailure func(error)) *recordedSession {
	t.Helper()
	var tick time.Duration
	wrapper, err := newRecordedSession(session, sink, func() time.Duration {
		tick += time.Millisecond
		return tick
	}, onFailure)
	require.NoError(t, err)
	return wrapper
}

func waitForCaptureChanges(t *testing.T, sink *captureTestSink, expected int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(sink.resizeEvents()) >= expected
	}, time.Second, time.Millisecond)
}

func requireChannelClosed(t *testing.T, windows <-chan essh.Window) {
	t.Helper()
	select {
	case _, open := <-windows:
		require.False(t, open)
	case <-time.After(time.Second):
		t.Fatal("window channel was not closed")
	}
}

type captureTestOutput struct {
	elapsed time.Duration
	stream  recording.OutputStream
	data    []byte
}

type captureTestResize struct {
	elapsed time.Duration
	columns uint32
	rows    uint32
}

type captureTestSink struct {
	mu        sync.Mutex
	outputs   []captureTestOutput
	resizes   []captureTestResize
	order     []string
	outputErr error
	resizeErr error
	changed   chan struct{}
}

func (this *captureTestSink) WriteOutput(elapsed time.Duration, stream recording.OutputStream, data []byte) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.outputs = append(this.outputs, captureTestOutput{elapsed: elapsed, stream: stream, data: append([]byte(nil), data...)})
	this.order = append(this.order, "output")
	return this.outputErr
}

func (this *captureTestSink) WriteResize(elapsed time.Duration, columns, rows uint32) error {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.resizes = append(this.resizes, captureTestResize{elapsed: elapsed, columns: columns, rows: rows})
	this.order = append(this.order, "resize")
	if this.changed != nil {
		select {
		case this.changed <- struct{}{}:
		default:
		}
	}
	return this.resizeErr
}

func (this *captureTestSink) outputEvents() []captureTestOutput {
	this.mu.Lock()
	defer this.mu.Unlock()
	return append([]captureTestOutput(nil), this.outputs...)
}

func (this *captureTestSink) resizeEvents() []captureTestResize {
	this.mu.Lock()
	defer this.mu.Unlock()
	return append([]captureTestResize(nil), this.resizes...)
}

func (this *captureTestSink) eventOrder() []string {
	this.mu.Lock()
	defer this.mu.Unlock()
	return append([]string(nil), this.order...)
}

type captureTestReadWriter struct {
	reader     bytes.Buffer
	writer     bytes.Buffer
	write      func([]byte) (int, error)
	writeCalls atomic.Int32
}

func (this *captureTestReadWriter) Read(value []byte) (int, error) {
	return this.reader.Read(value)
}

func (this *captureTestReadWriter) Write(value []byte) (int, error) {
	this.writeCalls.Add(1)
	if this.write != nil {
		return this.write(value)
	}
	return this.writer.Write(value)
}

type captureTestRequest struct {
	name      string
	wantReply bool
	payload   []byte
}

type captureTestSession struct {
	stdin       *captureTestReadWriter
	stdout      *captureTestReadWriter
	stderr      *captureTestReadWriter
	ctx         essh.Context
	user        string
	remoteAddr  net.Addr
	localAddr   net.Addr
	environment []string
	command     []string
	rawCommand  string
	subsystem   string
	permissions essh.Permissions
	pty         essh.Pty
	windows     <-chan essh.Window
	hasPty      bool

	exitCode        int
	signals         chan<- essh.Signal
	breaks          chan<- bool
	request         captureTestRequest
	closeCalls      atomic.Int32
	closeWriteCalls atomic.Int32
	ptyCalls        atomic.Int32
}

func newCaptureTestSession(ctx context.Context) *captureTestSession {
	sshCtx, ok := ctx.(essh.Context)
	if !ok {
		sshCtx = newCaptureTestContext(ctx)
	}
	return &captureTestSession{
		stdin:  &captureTestReadWriter{},
		stdout: &captureTestReadWriter{},
		stderr: &captureTestReadWriter{},
		ctx:    sshCtx,
	}
}

func (this *captureTestSession) Read(value []byte) (int, error)  { return this.stdin.Read(value) }
func (this *captureTestSession) Write(value []byte) (int, error) { return this.stdout.Write(value) }
func (this *captureTestSession) Close() error {
	this.closeCalls.Add(1)
	return nil
}
func (this *captureTestSession) CloseWrite() error {
	this.closeWriteCalls.Add(1)
	return nil
}
func (this *captureTestSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	this.request = captureTestRequest{name: name, wantReply: wantReply, payload: append([]byte(nil), payload...)}
	return true, nil
}
func (this *captureTestSession) Stderr() io.ReadWriter              { return this.stderr }
func (this *captureTestSession) User() string                       { return this.user }
func (this *captureTestSession) RemoteAddr() net.Addr               { return this.remoteAddr }
func (this *captureTestSession) LocalAddr() net.Addr                { return this.localAddr }
func (this *captureTestSession) Environ() []string                  { return append([]string(nil), this.environment...) }
func (this *captureTestSession) Exit(code int) error                { this.exitCode = code; return nil }
func (this *captureTestSession) Command() []string                  { return append([]string(nil), this.command...) }
func (this *captureTestSession) RawCommand() string                 { return this.rawCommand }
func (this *captureTestSession) Subsystem() string                  { return this.subsystem }
func (this *captureTestSession) PublicKey() essh.PublicKey          { return nil }
func (this *captureTestSession) Context() essh.Context              { return this.ctx }
func (this *captureTestSession) Permissions() essh.Permissions      { return this.permissions }
func (this *captureTestSession) Signals(signals chan<- essh.Signal) { this.signals = signals }
func (this *captureTestSession) Break(breaks chan<- bool)           { this.breaks = breaks }
func (this *captureTestSession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	this.ptyCalls.Add(1)
	return this.pty, this.windows, this.hasPty
}

type captureTestContext struct {
	context.Context
	sync.Mutex
	permissions essh.Permissions
	values      sync.Map
}

func newCaptureTestContext(ctx context.Context) *captureTestContext {
	return &captureTestContext{Context: ctx}
}

func (*captureTestContext) User() string                        { return "" }
func (*captureTestContext) SessionID() string                   { return "" }
func (*captureTestContext) ClientVersion() string               { return "" }
func (*captureTestContext) ServerVersion() string               { return "" }
func (*captureTestContext) RemoteAddr() net.Addr                { return nil }
func (*captureTestContext) LocalAddr() net.Addr                 { return nil }
func (this *captureTestContext) Permissions() *essh.Permissions { return &this.permissions }
func (this *captureTestContext) SetValue(key, value any)        { this.values.Store(key, value) }

type captureTestAddr string

func (captureTestAddr) Network() string     { return "test" }
func (this captureTestAddr) String() string { return string(this) }
