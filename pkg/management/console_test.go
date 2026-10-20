package management

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
)

// Prompt notifications synchronize tests with terminal-mode changes without
// inspecting a buffer concurrently with the authentication callbacks.
type consoleTestOutput struct {
	mutex   sync.Mutex
	buffer  bytes.Buffer
	changed chan struct{}
}

func newConsoleTestOutput() *consoleTestOutput {
	return &consoleTestOutput{changed: make(chan struct{}, 1)}
}

func (this *consoleTestOutput) Write(value []byte) (int, error) {
	this.mutex.Lock()
	n, err := this.buffer.Write(value)
	this.mutex.Unlock()
	select {
	case this.changed <- struct{}{}:
	default:
	}
	return n, err
}

func (this *consoleTestOutput) String() string {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.buffer.String()
}

func (this *consoleTestOutput) await(t *testing.T, prompt string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(this.String(), prompt) {
		select {
		case <-this.changed:
		case <-deadline.C:
			t.Fatalf("authentication prompt %q not reached: %q", prompt, this.String())
		}
	}
}

type consoleTestResult struct {
	line []byte
	err  error
}

func awaitConsoleTestResult(t *testing.T, done <-chan consoleTestResult) consoleTestResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("authentication input did not finish")
		return consoleTestResult{}
	}
}

func TestManagementConsoleRejectsNonterminalWithoutPrompt(t *testing.T) {
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), strings.NewReader("secret\n"), io.Discard, &output)
	line, err := readManagementPassword(ctx, "Password: ")
	require.ErrorContains(t, err, "needs a terminal")
	require.Nil(t, line)
	require.Empty(t, output.String())
}

func TestManagementConsoleAlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	line, err := readManagementPassword(ctx, "Password: ")
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, line)
}
