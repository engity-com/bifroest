package environment

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const localConPTYTestDiagnosticLimit = 1024

const localConPTYTestPhaseLimit = 64

func localConPTYTestPhaseName(phase string) string {
	if phase == "" || len(phase) > 64 {
		return "invalid"
	}
	for _, char := range phase {
		if char != '.' && char != '-' && (char < 'a' || char > 'z') {
			return "invalid"
		}
	}
	return phase
}

// Only test children install this observer. Emit bounded milestones immediately
// so killing a stuck child cannot discard its complete in-memory trace. No
// additional file flush, native state probe or shutdown operation is performed.
func localConPTYTestPhaseObserver(output io.Writer) func(string) {
	started := time.Now()
	var mutex sync.Mutex
	count := 0
	return func(phase string) {
		mutex.Lock()
		defer mutex.Unlock()
		if count == localConPTYTestPhaseLimit {
			return
		}
		count++
		_, _ = fmt.Fprintf(output, "conpty-test phase=%q elapsed=%s\n", localConPTYTestPhaseName(phase), time.Since(started))
	}
}

func localConPTYTestLastPhase(raw string) string {
	last := "unobserved"
	for line := range strings.SplitSeq(raw, "\n") {
		value, ok := strings.CutPrefix(line, "conpty-test phase=")
		if !ok {
			continue
		}
		value, _, ok = strings.Cut(value, " elapsed=")
		if !ok {
			continue
		}
		phase, err := strconv.Unquote(value)
		if err == nil && localConPTYTestPhaseName(phase) != "invalid" {
			last = phase
		}
	}
	return last
}

func localConPTYTestDiagnosticOutput(raw string) string {
	if len(raw) <= localConPTYTestDiagnosticLimit {
		return strconv.QuoteToASCII(raw)
	}
	half := localConPTYTestDiagnosticLimit / 2
	return strconv.QuoteToASCII(raw[:half]) + " [truncated] " + strconv.QuoteToASCII(raw[len(raw)-half:])
}

// Call only after Cmd.Wait joins the output copiers. Capture only the test
// fixture's output and cleanup results, never its environment or input frames.
func localConPTYTestTimeoutDiagnostic(phase string, pid int, timeoutElapsed, cleanupElapsed time.Duration, readyReceived bool, killErr, waitErr error, stdout, stderr string) string {
	return fmt.Sprintf("ConPTY timeout diagnostic (post-cleanup only; not native state at timeout): phase=%s pid=%d elapsedAtTimeout=%s elapsedAfterCleanup=%s readyReceivedBeforeTimeout=%t readyMarkerPostCleanup=%t lastObservedPhase=%q stdoutBytes=%d stderrBytes=%d kill=%s wait=%s stdout=%s stderr=%s",
		phase, pid, timeoutElapsed, cleanupElapsed, readyReceived, strings.Contains(stdout, localConPTYTestReady), localConPTYTestLastPhase(stderr), len(stdout), len(stderr),
		localConPTYTestDiagnosticOutput(fmt.Sprint(killErr)), localConPTYTestDiagnosticOutput(fmt.Sprint(waitErr)),
		localConPTYTestDiagnosticOutput(stdout), localConPTYTestDiagnosticOutput(stderr))
}

func TestLocalConPTYTestPhaseObserverBoundsConcurrentOutput(t *testing.T) {
	var output bytes.Buffer
	observe := localConPTYTestPhaseObserver(&output)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 32 {
				observe("library.bootstrap.begin")
			}
		})
	}
	workers.Wait()
	require.Equal(t, localConPTYTestPhaseLimit, strings.Count(output.String(), "conpty-test phase="))
	require.Equal(t, "library.bootstrap.begin", localConPTYTestLastPhase(output.String()))
	require.LessOrEqual(t, output.Len(), localConPTYTestPhaseLimit*128)
}

func TestLocalConPTYTestPhaseObserverRejectsInvalidLabels(t *testing.T) {
	for _, phase := range []string{"", "native path C:\\private", "secret\nvalue", strings.Repeat("x", 65), "\xff"} {
		var output bytes.Buffer
		localConPTYTestPhaseObserver(&output)(phase)
		require.Contains(t, output.String(), `phase="invalid"`)
		if phase != "" {
			require.NotContains(t, output.String(), phase)
		}
	}
}

func TestLocalConPTYTestLastPhaseIsExplicitlyPostCleanupAndUntruncated(t *testing.T) {
	stderr := "conpty-test phase=\"library.bootstrap.begin\" elapsed=1ms\n" +
		strings.Repeat("x", 2*localConPTYTestDiagnosticLimit) +
		"\nconpty-test phase=\"relay.console.begin\" elapsed=2ms\n" +
		strings.Repeat("x", 2*localConPTYTestDiagnosticLimit)
	diagnostic := localConPTYTestTimeoutDiagnostic("readiness", 42, 20*time.Second, 21*time.Second,
		false, nil, errors.New("exit status 1"), "", stderr)
	require.Contains(t, diagnostic, "post-cleanup only; not native state at timeout")
	require.Contains(t, diagnostic, `lastObservedPhase="relay.console.begin"`)
	require.Equal(t, "unobserved", localConPTYTestLastPhase("unrelated stderr\nconpty-test phase=invalid"))
	require.Equal(t, "unobserved", localConPTYTestLastPhase(`conpty-test phase="private\nvalue" elapsed=1ms`))
}

func TestLocalConPTYTestTimeoutDiagnosticLabelsPostCleanupCapture(t *testing.T) {
	stdout, stderr := "partial\x1b[0m\r\n\x00\xff", "relay diagnostic\n"
	diagnostic := localConPTYTestTimeoutDiagnostic("readiness", 42, 20*time.Second, 21*time.Second,
		false, nil, errors.New("exit status 1\n"), stdout, stderr)
	for _, expected := range []string{
		"post-cleanup only; not native state at timeout", "phase=readiness pid=42", "elapsedAtTimeout=20s elapsedAfterCleanup=21s",
		"readyReceivedBeforeTimeout=false readyMarkerPostCleanup=false",
		fmt.Sprintf("stdoutBytes=%d stderrBytes=%d", len(stdout), len(stderr)),
		`kill="<nil>" wait="exit status 1\n"`, `stdout="partial\x1b[0m\r\n\x00\xff"`, `stderr="relay diagnostic\n"`,
	} {
		require.Contains(t, diagnostic, expected)
	}
	for _, raw := range []string{"\x1b", "\r", "\n", "\x00", "\xff"} {
		require.NotContains(t, diagnostic, raw, "raw control/binary output must not enter the log")
	}
}

func TestLocalConPTYTestTimeoutDiagnosticBoundsOutputWithoutHidingMarkerStatus(t *testing.T) {
	stdout := strings.Repeat("\x00", localConPTYTestDiagnosticLimit) + localConPTYTestReady + strings.Repeat("\xff", localConPTYTestDiagnosticLimit)
	snapshot := localConPTYTestDiagnosticOutput(stdout)
	require.Contains(t, snapshot, " [truncated] ")
	require.Contains(t, snapshot, `"\x00`)
	require.Contains(t, snapshot, `\xff"`)
	require.NotContains(t, snapshot, localConPTYTestReady, "the marker is outside the retained head/tail")
	require.LessOrEqual(t, len(snapshot), 4*localConPTYTestDiagnosticLimit+len(" [truncated] ")+4)
	require.Equal(t, strconv.QuoteToASCII(strings.Repeat("x", localConPTYTestDiagnosticLimit)),
		localConPTYTestDiagnosticOutput(strings.Repeat("x", localConPTYTestDiagnosticLimit)))

	diagnostic := localConPTYTestTimeoutDiagnostic("exit", 42, 20*time.Second, 21*time.Second, true,
		errors.New(stdout), errors.New(stdout), stdout, stdout)
	require.Contains(t, diagnostic, "phase=exit")
	require.Contains(t, diagnostic, "readyReceivedBeforeTimeout=true readyMarkerPostCleanup=true")
	require.Contains(t, diagnostic, fmt.Sprintf("stdoutBytes=%d stderrBytes=%d", len(stdout), len(stdout)))
	require.Equal(t, 4, strings.Count(diagnostic, " [truncated] "), "both streams and cleanup errors are bounded")
	require.LessOrEqual(t, len(diagnostic), 4*len(snapshot)+512)
}
