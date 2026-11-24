package environment

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	localConPTYTestReady    = "native-console-child ready"
	localConPTYTestContinue = "continue-roundtrip"
	localConPTYTestFinished = "native-console-child roundtrip-complete"
)

func runLocalConPTYTestHandshake(input io.Reader, output io.Writer) error {
	write := func(marker string) error {
		text := marker + "\r\n"
		written, err := io.WriteString(output, text)
		if err == nil && written != len(text) {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := write(localConPTYTestReady); err != nil {
		return err
	}
	// Console line input completes on Enter; bound even an invalid reply.
	line, err := bufio.NewReader(io.LimitReader(input, int64(len(localConPTYTestContinue)+2))).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r") != localConPTYTestContinue {
		return fmt.Errorf("unexpected ConPTY test acknowledgement")
	}
	// This final output is not acknowledged: the relay must drain it at exit.
	return write(localConPTYTestFinished)
}

// Only exec.Cmd's output copier writes this buffer. The parent receives a copy
// at readiness and does not inspect the mutable buffer until Cmd.Wait joins it.
type localConPTYTestOutput struct {
	buffer bytes.Buffer
	ready  chan string
}

func (w *localConPTYTestOutput) Write(data []byte) (int, error) {
	written, err := w.buffer.Write(data)
	if w.ready != nil && bytes.Contains(w.buffer.Bytes(), []byte(localConPTYTestReady)) {
		w.ready <- w.String()
		w.ready = nil
	}
	return written, err
}

func (w *localConPTYTestOutput) String() string { return w.buffer.String() }

func (w *localConPTYTestOutput) Len() int { return w.buffer.Len() }

func TestLocalConPTYTestHandshake(t *testing.T) {
	for _, reply := range []string{localConPTYTestContinue + "\n", localConPTYTestContinue + "\r\n", "wrong\n", "", localConPTYTestContinue, strings.Repeat("x", 100)} {
		t.Run(fmt.Sprintf("reply=%q", reply), func(t *testing.T) {
			var output bytes.Buffer
			err := runLocalConPTYTestHandshake(strings.NewReader(reply), &output)
			if reply == localConPTYTestContinue+"\n" || reply == localConPTYTestContinue+"\r\n" {
				require.NoError(t, err)
				require.Equal(t, localConPTYTestReady+"\r\n"+localConPTYTestFinished+"\r\n", output.String())
			} else {
				require.Error(t, err)
				require.Equal(t, localConPTYTestReady+"\r\n", output.String(), "an invalid/missing acknowledgement must not produce the final marker")
			}
		})
	}
}

func TestLocalConPTYTestHandshakeWaitsForObservedReady(t *testing.T) {
	input, reply := io.Pipe()
	defer func() { _ = input.Close() }()
	defer func() { _ = reply.Close() }()
	ready := make(chan string, 1)
	output := &localConPTYTestOutput{ready: ready}
	done := make(chan error, 1)
	go func() { done <- runLocalConPTYTestHandshake(input, output) }()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	select {
	case prefix := <-ready:
		require.Contains(t, prefix, localConPTYTestReady)
		require.NotContains(t, prefix, localConPTYTestFinished)
	case err := <-done:
		t.Fatalf("handshake finished before acknowledgement: %v", err)
	case <-timeout.C:
		t.Fatal("handshake did not announce readiness")
	}
	_, err := io.WriteString(reply, localConPTYTestContinue+"\r\n")
	require.NoError(t, err)
	select {
	case err := <-done:
		require.NoError(t, err)
		require.Contains(t, output.String(), localConPTYTestFinished)
	case <-timeout.C:
		t.Fatal("handshake did not finish after acknowledgement")
	}
}

func TestLocalConPTYTestOutputNotifiesOnlyAfterReady(t *testing.T) {
	for split := range len(localConPTYTestReady) {
		t.Run(fmt.Sprintf("split=%d", split), func(t *testing.T) {
			ready := make(chan string, 1)
			output := &localConPTYTestOutput{ready: ready}
			prefix := "identity\r\nnative-console=80x25\r\n"
			_, err := output.Write([]byte(prefix + localConPTYTestReady[:split]))
			require.NoError(t, err)
			select {
			case <-ready:
				t.Fatal("incomplete output must not allow the child to exit")
			default:
			}
			rest := localConPTYTestReady[split:]
			_, err = io.Copy(output, io.LimitReader(strings.NewReader(rest), int64(len(rest))))
			require.NoError(t, err)
			select {
			case snapshot := <-ready:
				require.Equal(t, prefix+localConPTYTestReady, snapshot)
			default:
				t.Fatal("complete readiness marker was not observed")
			}
			_, err = output.Write([]byte("\r\n" + localConPTYTestReady + "\r\n" + localConPTYTestFinished))
			require.NoError(t, err)
			select {
			case <-ready:
				t.Fatal("readiness must be reported only once")
			default:
			}
			require.Contains(t, output.String(), localConPTYTestFinished)
		})
	}
}
