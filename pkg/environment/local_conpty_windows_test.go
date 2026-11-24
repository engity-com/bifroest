//go:build windows

package environment

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/engity-com/bifroest/internal/conpty"
)

func TestLocalConPTYFrame(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'D', data: []byte("hello")}))
	require.Equal(t, byte('D'), buf.Bytes()[0])
	require.Equal(t, uint32(5), binary.LittleEndian.Uint32(buf.Bytes()[1:5]))
	require.Equal(t, "hello", string(buf.Bytes()[5:]))
}

func TestLocalConPTYReleaseDrainsBeforeCloseAndPreservesOutputFailure(t *testing.T) {
	for _, released := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("released=%t/failure=%t", released, failure), func(t *testing.T) {
				var steps []string
				var expected error
				if failure {
					expected = errors.New("output forwarding failed")
				}
				var releaseErr error
				if !released {
					releaseErr = errors.New("release failed")
				}
				err := finishLocalConPTYOutput(func() error {
					steps = append(steps, "release")
					return releaseErr
				}, func() error {
					steps = append(steps, "drain")
					return expected
				}, func() { steps = append(steps, "close") })
				if expected != nil {
					require.ErrorIs(t, err, expected)
				}
				if releaseErr != nil {
					require.ErrorIs(t, err, releaseErr)
				}
				if expected == nil && releaseErr == nil {
					require.NoError(t, err)
				}
				if released {
					require.Equal(t, []string{"release", "drain", "close"}, steps)
				} else {
					require.Equal(t, []string{"release", "close", "drain"}, steps)
				}
			})
		}
	}
}

func TestLocalConPTYRootObservationDoesNotInventCompletionOnProbeFailure(t *testing.T) {
	for _, test := range []struct {
		name   string
		status uint32
		err    error
		want   string
	}{
		{"confirmed exit", windows.WAIT_OBJECT_0, nil, "exited"},
		{"still running", uint32(windows.WAIT_TIMEOUT), nil, "running"},
		{"unknown status", uint32(windows.WAIT_FAILED), nil, "unknown"},
		{"probe denied", windows.WAIT_OBJECT_0, windows.ERROR_ACCESS_DENIED, "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			actual := observeLocalConPTYRootState(func() (uint32, error) {
				calls++
				return test.status, test.err
			})
			require.Equal(t, test.want, actual)
			require.Equal(t, 1, calls, "observations neither wait/retry nor manufacture an exit")
		})
	}
}

func TestLocalConPTYCommandFrame(t *testing.T) {
	argv := []string{`C:\Windows\System32\cmd.exe`, "/C", "echo hello"}
	payload, err := json.Marshal(argv)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'C', data: payload}))
	parsed, err := ReadLocalConPTYCommand(&buf)
	require.NoError(t, err)
	require.Equal(t, argv, parsed)

	buf.Reset()
	require.NoError(t, writeLocalConPTYFrame(&buf, localConPTYFrame{kind: 'R', data: []byte{80, 0, 25, 0}}))
	_, err = ReadLocalConPTYCommand(&buf)
	require.ErrorContains(t, err, "invalid ConPTY command frame")
}

func TestLocalConPTYRelayExitStatus(t *testing.T) {
	for _, code := range []int{0, 1, 255, 65535} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var frame bytes.Buffer
			require.NoError(t, WriteLocalConPTYRelayExitStatus(&frame, code))
			status := &localConPTYRelayStatusWriter{}
			_, err := status.Write([]byte("relay diagnostic\n"))
			require.NoError(t, err)
			_, err = status.Write(frame.Bytes()[:3])
			require.NoError(t, err)
			_, err = status.Write(frame.Bytes()[3:])
			require.NoError(t, err)
			got, diagnostic, err := status.exitStatus()
			require.NoError(t, err)
			require.Equal(t, code, got)
			require.Equal(t, "relay diagnostic", diagnostic)
		})
	}
}

func TestLocalConPTYRelayExitStatusFailsClosed(t *testing.T) {
	var valid bytes.Buffer
	require.NoError(t, WriteLocalConPTYRelayExitStatus(&valid, 1))
	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "missing", data: []byte("relay failed\n"), want: "missing"},
		{name: "invalid", data: []byte(localConPTYRelayExitPrefix + "00000x01\n"), want: "invalid"},
		{name: "invalid sign", data: []byte(localConPTYRelayExitPrefix + "+0000001\n"), want: "invalid"},
		{name: "duplicate", data: bytes.Repeat(valid.Bytes(), 2), want: "duplicate"},
		{name: "trailing output", data: append(bytes.Clone(valid.Bytes()), []byte("later\n")...), want: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := &localConPTYRelayStatusWriter{}
			_, err := status.Write(tc.data)
			require.NoError(t, err)
			_, _, err = status.exitStatus()
			require.ErrorContains(t, err, tc.want)
		})
	}
	status := &localConPTYRelayStatusWriter{}
	large := bytes.Repeat([]byte("x"), 16*1024)
	_, err := status.Write(large)
	require.NoError(t, err)
	_, err = status.Write(valid.Bytes())
	require.NoError(t, err)
	require.Equal(t, len(status.tail), status.length)
	code, diagnostic, err := status.exitStatus()
	require.NoError(t, err)
	require.Equal(t, 1, code)
	require.Contains(t, diagnostic, "[truncated]")
	status = &localConPTYRelayStatusWriter{}
	_, err = status.Write(bytes.Repeat([]byte("x"), len(status.tail)))
	require.NoError(t, err)
	require.False(t, status.truncated)
	require.ErrorContains(t, WriteLocalConPTYRelayExitStatus(io.Discard, -1), "invalid")
}

func TestLocalConPTYRelayRoundTrip(t *testing.T) {
	testLocalConPTYRelayRuns(t, false)
}

func TestLocalConPTYRelayImmediateExit(t *testing.T) {
	// Nano Server 2022 intermittently loses all first-use output in this case.
	// Keep that stricter stress case separate from the interactive smoke test.
	if os.Getenv("BIFROEST_TEST_CONPTY_IMMEDIATE_EXIT") != "1" {
		t.Skip("set BIFROEST_TEST_CONPTY_IMMEDIATE_EXIT=1 to stress first-use output from immediately exiting ConPTY clients")
	}
	testLocalConPTYRelayRuns(t, true)
}

func testLocalConPTYRelayRuns(t *testing.T, immediateExit bool) {
	t.Helper()
	if os.Getenv("BIFROEST_CONPTY_RELAY_TEST_CHILD") == "1" {
		var observation localConPTYRelayObservation
		argv := []string{os.Args[0], "local-windows-console-child"}
		if os.Getenv("BIFROEST_CONPTY_TEST_NATIVE_CONSOLE_WRITE") == "1" {
			argv[1] = "local-windows-native-console-child"
		}
		if os.Getenv("BIFROEST_CONPTY_TEST_RAW_FILE_WRITE") == "1" {
			argv[1] = "local-windows-file-console-child"
		}
		if os.Getenv("BIFROEST_CONPTY_TEST_EXIT") == "7" {
			argv = append(argv, "7")
		} else if os.Getenv("BIFROEST_CONPTY_TEST_EXPLICIT_ZERO_ARG") == "1" {
			argv = append(argv, "0")
		}
		if !immediateExit {
			if len(argv) == 2 {
				argv = append(argv, "0")
			}
			argv = append(argv, "roundtrip")
		}
		code, err := runLocalConPTYRelay(80, 25, argv, &observation)
		// This is observed only after the production relay has returned; it
		// does not claim any earlier native flush/shutdown event was observed.
		diagnostic := fmt.Sprintf("conpty-test relay-returned exit=%d error=%t accounted=%t activeProcesses=%d released=%t copiedBytes=%d stdoutType=%d outputPipeType=%d emptyReads=%d rootAtInputEOF=%q rootAtOutputEOF=%q rootAtNativeEOF=%q eofBeforeClose=%t\n", code, err != nil, observation.jobQueryOK, observation.activeProcesses, observation.released, observation.outputBytes, observation.stdoutType, observation.outputPipeType, observation.emptyReads, observation.rootAtInputEOF, observation.rootAtOutputEOF, observation.rootAtNativeEOF, observation.eofBeforeClose)
		written, diagnosticErr := fmt.Fprint(os.Stderr, diagnostic)
		if err != nil || diagnosticErr != nil || written != len(diagnostic) {
			os.Exit(1)
		}
		os.Exit(code)
	}
	if err := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find(); err != nil {
		t.Skip("ConPTY is not available on this Windows version")
	}
	statuses := []int{0, 7}
	if os.Getenv("BIFROEST_CONPTY_TEST_NONZERO_FIRST") == "1" {
		statuses[0], statuses[1] = statuses[1], statuses[0]
	}
	// Independent fresh-host executions, not retries. The smoke test exchanges
	// input before exit; the opt-in stress test also demands output without it.
	testName := t.Name()
	for iteration := range 8 {
		for _, status := range statuses {
			t.Run(fmt.Sprintf("run=%d/exit=%d", iteration, status), func(t *testing.T) {
				testLocalConPTYRelayRoundTrip(t, testName, status, immediateExit)
			})
		}
	}
}

func testLocalConPTYRelayRoundTrip(t *testing.T, testName string, status int, immediateExit bool) {
	t.Helper()
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	require.NoError(t, err)
	version := windows.RtlGetVersion()
	t.Logf("ConPTY library=%s systemReleaseAvailable=%t runtimeOS=%d.%d.%d nativeConsoleWrite=%t rawFileWrite=%t nonzeroFirst=%t explicitZeroArg=%t nanoMarker=%t (child exit 2 means unexpected geometry)", conpty.Version, windows.NewLazySystemDLL("kernel32.dll").NewProc("ReleasePseudoConsole").Find() == nil, version.MajorVersion, version.MinorVersion, version.BuildNumber, os.Getenv("BIFROEST_CONPTY_TEST_NATIVE_CONSOLE_WRITE") == "1", os.Getenv("BIFROEST_CONPTY_TEST_RAW_FILE_WRITE") == "1", os.Getenv("BIFROEST_CONPTY_TEST_NONZERO_FIRST") == "1", os.Getenv("BIFROEST_CONPTY_TEST_EXPLICIT_ZERO_ARG") == "1", os.Getenv("BIFROEST_TEST_NANOSERVER_IN_CONTAINER") == "1")
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "BIFROEST_CONPTY_RELAY_TEST_CHILD=1", "BIFROEST_CONPTY_TEST_EXIT="+strconv.Itoa(status))
	ready := make(chan string, 1)
	stdout := &localConPTYTestOutput{}
	if !immediateExit {
		stdout.ready = ready
	}
	var stderr bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	defer func() { _ = stdin.Close() }()
	require.NoError(t, cmd.Start())
	started := time.Now()
	result := make(chan error, 1)
	go func() { result <- cmd.Wait() }()
	waited := false
	readyReceived := false
	timeoutPhase := ""
	var timeoutElapsed time.Duration
	defer func() {
		if !waited {
			killErr := cmd.Process.Kill()
			waitErr := <-result
			if timeoutPhase != "" {
				// Wait has joined both output copiers. These buffers describe only
				// post-cleanup capture, not native state at the timeout deadline.
				t.Log(localConPTYTestTimeoutDiagnostic(timeoutPhase, cmd.Process.Pid,
					timeoutElapsed, time.Since(started), readyReceived, killErr, waitErr,
					stdout.String(), stderr.String()))
			}
		}
	}()
	timeout := time.NewTimer(20 * time.Second)
	defer timeout.Stop()
	if !immediateExit {
		select {
		case prefix := <-ready:
			readyReceived = true
			require.Contains(t, strings.ToUpper(prefix), strings.ToUpper(self.User.Sid.String()))
			require.Contains(t, prefix, "native-console=80x25")
			require.Contains(t, prefix, "native-console-child write-success=true ")
			require.NoError(t, writeLocalConPTYFrame(stdin, localConPTYFrame{kind: 'D', data: []byte(localConPTYTestContinue + "\r")}))
		case err := <-result:
			waited = true
			t.Fatalf("ConPTY relay exited before the roundtrip acknowledgement: %v; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
		case <-timeout.C:
			timeoutPhase, timeoutElapsed = "readiness", time.Since(started)
			t.Fatal("ConPTY relay did not produce readiness output within 20 seconds")
		}
	}
	select {
	case err := <-result:
		waited = true
		t.Logf("ConPTY test parent wait completed: error=%t relayReturnSuccessMarker=%t childWriteSuccessMarker=%t stdoutBytes=%d stderrBytes=%d",
			err != nil,
			strings.HasPrefix(stderr.String(), fmt.Sprintf("conpty-test relay-returned exit=%d error=false ", status)),
			strings.Contains(stdout.String(), "native-console-child write-success=true "),
			stdout.Len(), stderr.Len())
		t.Logf("bounded relay observation: %s", strings.TrimSpace(stderr.String()))
		if status == 0 {
			require.NoError(t, err, "%s", stderr.String())
		} else {
			var exited *exec.ExitError
			require.ErrorAs(t, err, &exited, "%s", stderr.String())
			require.Equal(t, status, exited.ExitCode())
		}
		require.Contains(t, stderr.String(), fmt.Sprintf("conpty-test relay-returned exit=%d error=false ", status))
		require.Contains(t, stderr.String(), "released=true")
		require.Contains(t, stderr.String(), "eofBeforeClose=true", "native EOF must precede ClosePseudoConsole")
	case <-timeout.C:
		timeoutPhase, timeoutElapsed = "exit", time.Since(started)
		t.Fatal("ConPTY relay did not stop within 20 seconds")
	}
	require.Contains(t, strings.ToUpper(stdout.String()), strings.ToUpper(self.User.Sid.String()))
	require.Contains(t, stdout.String(), "native-console=80x25")
	require.Contains(t, stdout.String(), "native-console-child write-success=true ")
	if !immediateExit {
		require.Contains(t, stdout.String(), localConPTYTestFinished, "the unacknowledged final output must survive immediate child exit")
	}
}

func TestLocalConPTYChildStandardHandlesAreClearedAndRestored(t *testing.T) {
	for _, failure := range []string{"", "clear", "create"} {
		t.Run(failure, func(t *testing.T) {
			ids := []uint32{windows.STD_INPUT_HANDLE, windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE}
			table := map[uint32]windows.Handle{ids[0]: 11, ids[1]: 22, ids[2]: 33}
			created := false
			err := withLocalConPTYChildStandardHandles(func(id uint32) (windows.Handle, error) { return table[id], nil }, func(id uint32, value windows.Handle) error {
				if failure == "clear" && value == 0 && id == ids[1] {
					return fmt.Errorf("clear failed")
				}
				table[id] = value
				return nil
			}, func() error {
				created = true
				for _, id := range ids {
					require.Zero(t, table[id])
				}
				if failure == "create" {
					return fmt.Errorf("create failed")
				}
				return nil
			})
			if failure == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, failure != "clear", created)
			require.Equal(t, map[uint32]windows.Handle{ids[0]: 11, ids[1]: 22, ids[2]: 33}, table)
		})
	}
}
