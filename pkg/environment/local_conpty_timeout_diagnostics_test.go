package environment

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const localConPTYTestDiagnosticLimit = 1024

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
	return fmt.Sprintf("ConPTY timeout diagnostic (post-cleanup only; not native state at timeout): phase=%s pid=%d elapsedAtTimeout=%s elapsedAfterCleanup=%s readyReceivedBeforeTimeout=%t readyMarkerPostCleanup=%t stdoutBytes=%d stderrBytes=%d kill=%s wait=%s stdout=%s stderr=%s",
		phase, pid, timeoutElapsed, cleanupElapsed, readyReceived, strings.Contains(stdout, localConPTYTestReady), len(stdout), len(stderr),
		localConPTYTestDiagnosticOutput(fmt.Sprint(killErr)), localConPTYTestDiagnosticOutput(fmt.Sprint(waitErr)),
		localConPTYTestDiagnosticOutput(stdout), localConPTYTestDiagnosticOutput(stderr))
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
