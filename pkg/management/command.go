package management

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	cli "github.com/echocat/cli4g"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/transport"
)

// sshCommand owns one invocation's connection, session and diagnostics. Callers
// consume stdout according to their protocol, then check the SSH exit status.
type sshCommand struct {
	client      *ssh.Client
	session     *ssh.Session
	stdout      io.Reader
	stderr      diagnosticOutput
	diagnostics io.Writer
	release     func()
}

func (target Target) startWireCommand(ctx context.Context, command string, args ...string) (*sshCommand, error) {
	encoded, err := transport.EncodeWireRequest(args)
	if err != nil {
		return nil, err
	}
	return target.startCommand(ctx, command, bytes.NewReader(encoded))
}

func (target Target) startCommand(ctx context.Context, command string, input io.Reader) (*sshCommand, error) {
	client, release, err := connect(ctx, target)
	if err != nil {
		return nil, err
	}
	result := &sshCommand{client: client, release: release, diagnostics: cli.StderrOfContext(ctx)}
	started := false
	defer func() {
		if !started {
			result.close()
		}
	}()
	result.session, err = client.NewSession()
	if err != nil {
		return nil, err
	}
	result.session.Stdin = input
	result.session.Stderr = &result.stderr
	result.stdout, err = result.session.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := result.session.Start(command); err != nil {
		return nil, err
	}
	started = true
	return result, nil
}

func (this *sshCommand) close() {
	if this.session != nil {
		_ = this.session.Close()
	}
	this.release()
}

func (this *sshCommand) failure(operation string, err error) error {
	return fmt.Errorf("%s: %w: %s", operation, err, strings.TrimSpace(this.stderr.String()))
}

func (this *sshCommand) wait(operation string) error {
	if err := this.session.Wait(); err != nil {
		return this.failure(operation, err)
	}
	return this.stderr.forwardTo(this.diagnostics)
}

// Stop the peer before waiting when a streaming decoder or local writer fails.
// Otherwise a producer still writing stdout/stderr could keep Wait blocked.
func (this *sshCommand) abort(operation string, err error) error {
	_ = this.client.Close()
	_ = this.session.Wait()
	return this.failure(operation, err)
}

func (this *sshCommand) readResponse(maximum int64, description, operation string) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(this.stdout, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", description, maximum)
	}
	if err := this.wait(operation); err != nil {
		return nil, err
	}
	return content, nil
}

// diagnosticOutput captures a bounded stderr prefix while SSH may still be writing.
type diagnosticOutput struct {
	mutex     sync.Mutex
	buffer    bytes.Buffer
	truncated bool
}

const maximumDiagnosticBytes = 16 << 10

func (this *diagnosticOutput) Write(p []byte) (int, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	remaining := maximumDiagnosticBytes - this.buffer.Len()
	if len(p) > remaining {
		this.truncated = true
	}
	if remaining > 0 {
		_, _ = this.buffer.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}

func (this *diagnosticOutput) String() string {
	content, _ := this.snapshot()
	return content
}

func (this *diagnosticOutput) snapshot() (string, bool) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	return this.buffer.String(), this.truncated
}

// Forward only after Wait has drained SSH stderr. A slow local diagnostic
// writer must not block the remote producer while its response is being read.
func (this *diagnosticOutput) forwardTo(output io.Writer) error {
	if output == nil {
		return nil
	}
	content, truncated := this.snapshot()
	if content == "" {
		return nil
	}
	if truncated {
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += fmt.Sprintf("[remote diagnostics truncated after %d bytes]\n", maximumDiagnosticBytes)
	}
	written, err := io.WriteString(output, content)
	if err == nil && written != len(content) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("cannot write remote diagnostics: %w", err)
	}
	return nil
}
