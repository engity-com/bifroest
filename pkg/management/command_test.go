package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/recording"
)

type managementCommandTestCase struct {
	name     string
	command  string
	args     []string
	buffered bool
	run      func(context.Context, Target, io.Writer, string) error
	response func(io.Writer) error
}

func managementCommandTestCases(t *testing.T) []managementCommandTestCase {
	t.Helper()
	id, err := recording.NewId()
	require.NoError(t, err)
	payload := []byte("artifact bytes")
	digest := sha256.Sum256(payload)
	hash := hex.EncodeToString(digest[:])
	producer := strings.Repeat("a", 64)
	return []managementCommandTestCase{
		{
			name: "metadata", command: transport.WireCommand, args: []string{"flow", "ls"}, buffered: true,
			run: func(ctx context.Context, target Target, _ io.Writer, _ string) error {
				return target.Run(ctx, "flow", "ls", "--format=json")
			},
			response: func(output io.Writer) error {
				encoded, err := transport.EncodeWireResult([]model.FlowSummary{{Name: "production"}})
				if err != nil {
					return err
				}
				_, err = output.Write(encoded)
				return err
			},
		},
		{
			name: "version", command: "version --long=false", buffered: true,
			run: func(ctx context.Context, target Target, _ io.Writer, _ string) error {
				return target.RunDirect(ctx, "version --long=false")
			},
			response: func(output io.Writer) error {
				_, err := io.WriteString(output, "Bifroest test\n")
				return err
			},
		},
		{
			name: "key", command: transport.WireCommand, args: []string{"key", "export", "ca", "gateway"}, buffered: true,
			run: func(ctx context.Context, target Target, output io.Writer, _ string) error {
				content, err := target.ExportKey(ctx, "key", "export", "ca", "gateway")
				if err != nil {
					return err
				}
				_, err = output.Write(content)
				return err
			},
			response: func(output io.Writer) error {
				encoded, err := transport.EncodeWireResult([]byte("public key\n"))
				if err != nil {
					return err
				}
				_, err = output.Write(encoded)
				return err
			},
		},
		{
			name: "recording-list", command: transport.WireRecordingListStreamCommand, args: []string{"recording", "ls", "default"},
			run: func(ctx context.Context, target Target, _ io.Writer, _ string) error {
				return target.Run(ctx, "recording", "ls", "default", "--format=json")
			},
			response: func(output io.Writer) error {
				if err := transport.WriteRecordingStreamEntry(output, model.RecordingView{ID: id.String()}); err != nil {
					return err
				}
				return transport.WriteRecordingStreamEnd(output, 1)
			},
		},
		{
			name: "recording", command: transport.WireRecordingCommand, args: []string{"recording", "default", id.String()},
			run: func(ctx context.Context, target Target, output io.Writer, _ string) error {
				_, err := DownloadRecording(ctx, target, "default", id.String(), output)
				return err
			},
			response: func(output io.Writer) error {
				return transport.WriteRecordingArtifact(output, transport.RecordingArtifactHeader{
					Version: 1, ID: id.String(), ProducerID: producer, Size: int64(len(payload)), SHA256: hash,
				}, bytes.NewReader(payload))
			},
		},
		{
			name: "audit", command: transport.WireAuditCommand, args: []string{"auditlog", "default"},
			run: func(ctx context.Context, target Target, _ io.Writer, root string) error {
				_, err := DownloadAuditSnapshot(ctx, target, "default", root)
				return err
			},
			response: func(output io.Writer) error {
				encoded, err := cbor.Marshal(transport.AuditSnapshotHeader{
					Version: 1, Name: "default", Producer: producer,
					Files: []transport.AuditSnapshotEntry{{Name: "head.cbor", Size: int64(len(payload)), SHA256: hash}},
				})
				if err != nil {
					return err
				}
				if err := binary.Write(output, binary.BigEndian, uint32(len(encoded))); err != nil {
					return err
				}
				if _, err := output.Write(encoded); err != nil {
					return err
				}
				_, err = output.Write(payload)
				return err
			},
		},
	}
}

func checkManagementCommandRequest(channel ssh.Channel, expected []string) error {
	if len(expected) == 0 {
		return nil // Direct version commands carry no wire request.
	}
	args, err := transport.DecodeWireRequest(channel)
	if err != nil {
		return err
	}
	if !slices.Equal(args, expected) {
		return fmt.Errorf("unexpected command args %v, expected %v", args, expected)
	}
	return nil
}

func TestManagementCommandsRequireSuccessfulSSHExit(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				if _, err := io.WriteString(channel.Stderr(), "server operation incomplete\n"); err != nil {
					return err
				}
				if err := test.response(channel); err != nil {
					return err
				}
				_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{23}))
				return err
			})
			var output, diagnostic bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, &diagnostic)
			err := test.run(ctx, target, &output, t.TempDir())
			require.ErrorContains(t, err, "server operation incomplete")
			require.Empty(t, diagnostic.Bytes(), "failed-command diagnostics are already included in the returned error")
			var exit *ssh.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, 23, exit.ExitStatus())
			if test.buffered {
				require.Empty(t, output.Bytes(), "failed commands must not publish their buffered response")
			} else if test.name == "recording-list" {
				require.False(t, json.Valid(output.Bytes()), "a failed stream must not be completed")
			}
			require.NoError(t, <-done)
		})
	}
}

func TestManagementCommandsCancelOpenRemoteStreams(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			received := make(chan struct{})
			target, serverDone := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				close(received)
				for {
					if _, err := io.WriteString(channel.Stderr(), "still waiting\n"); err != nil {
						return nil
					}
					time.Sleep(time.Millisecond)
				}
			})
			var output bytes.Buffer
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			root := t.TempDir()
			finished := make(chan error, 1)
			go func() { finished <- test.run(ctx, target, &output, root) }()
			select {
			case <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("server did not receive the command")
			}
			cancel()
			select {
			case err := <-finished:
				require.Error(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("command did not stop after cancellation")
			}
			select {
			case err := <-serverDone:
				require.NoError(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("server connection remained open after cancellation")
			}
		})
	}
}

func TestManagementBufferedResponsesRejectOversizedOutput(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		if !test.buffered {
			continue
		}
		t.Run(test.name, func(t *testing.T) {
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				chunk := bytes.Repeat([]byte{'x'}, 32<<10)
				for {
					if _, err := channel.Write(chunk); err != nil {
						return nil
					}
				}
			})
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			err := test.run(ctx, target, &output, t.TempDir())
			maximum := transport.MaxWireResultBytes
			if test.name == "version" {
				maximum = 64 << 10
			}
			require.ErrorContains(t, err, fmt.Sprintf("exceeds %d bytes", maximum))
			require.Empty(t, output.Bytes())
			require.NoError(t, ctx.Err(), "response limits must not wait for a remote exit status")
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("oversized response producer was not stopped")
			}
		})
	}
}

func TestManagementCommandsForwardSuccessfulDiagnostics(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			const warning = "remote operation warning\n"
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				if _, err := io.WriteString(channel.Stderr(), warning); err != nil {
					return err
				}
				if err := test.response(channel); err != nil {
					return err
				}
				_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return err
			})
			var output, diagnostic bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, &diagnostic)
			require.NoError(t, test.run(ctx, target, &output, t.TempDir()))
			require.Equal(t, warning, diagnostic.String())
			require.NotContains(t, output.String(), warning)
			require.NoError(t, <-done)
		})
	}
}

type failedDiagnosticOutput struct{}

func (failedDiagnosticOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestManagementCommandsPropagateDiagnosticOutputFailure(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				if _, err := io.WriteString(channel.Stderr(), "warning that cannot be delivered\n"); err != nil {
					return err
				}
				if err := test.response(channel); err != nil {
					return err
				}
				_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
				return err
			})
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, failedDiagnosticOutput{})
			err := test.run(ctx, target, &output, t.TempDir())
			require.ErrorIs(t, err, io.ErrClosedPipe)
			require.ErrorContains(t, err, "cannot write remote diagnostics")
			if test.buffered {
				require.Empty(t, output.Bytes())
			} else if test.name == "recording-list" {
				require.False(t, json.Valid(output.Bytes()), "undeliverable diagnostics must not complete the stream")
			}
			require.NoError(t, <-done)
		})
	}
}

func TestManagementMalformedResponsesAbortBeforeWaitingForRemoteExit(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		if test.name == "version" {
			continue
		} // Fixed human-readable version output has no framed decoder.
		t.Run(test.name, func(t *testing.T) {
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				if _, err := io.WriteString(channel.Stderr(), "malformed transfer diagnostic\n"); err != nil {
					return err
				}
				if _, err := channel.Write([]byte{0xff}); err != nil {
					return err
				}
				if err := channel.CloseWrite(); err != nil {
					return err
				}
				// Stdout is finished, but the operation deliberately has no exit.
				// Unknown requests are refused by the normal client until it aborts.
				for {
					if _, err := channel.SendRequest("bifroest-test-pending", true, nil); err != nil {
						return nil
					}
				}
			})
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			err := test.run(ctx, target, &output, t.TempDir())
			require.Error(t, err)
			require.ErrorContains(t, err, "malformed transfer diagnostic")
			require.NoError(t, ctx.Err(), "malformed data must abort before waiting for remote exit")
			require.Empty(t, output.Bytes())
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("malformed response producer was not stopped")
			}
		})
	}
}

func TestManagementCompletePayloadWithoutSSHExitStatusIsNeverSuccess(t *testing.T) {
	for _, test := range managementCommandTestCases(t) {
		t.Run(test.name, func(t *testing.T) {
			target, done := managementSSHTestServer(t, test.command, func(channel ssh.Channel) error {
				if err := checkManagementCommandRequest(channel, test.args); err != nil {
					return err
				}
				return test.response(channel) // Channel closes without exit-status.
			})
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
			err := test.run(ctx, target, &output, t.TempDir())
			require.Error(t, err)
			var missing *ssh.ExitMissingError
			require.ErrorAs(t, err, &missing)
			if test.buffered {
				require.Empty(t, output.Bytes())
			} else if test.name == "recording-list" {
				require.False(t, json.Valid(output.Bytes()), "valid rows/end/EOF alone must not complete a streamed result")
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("missing-exit response was not released")
			}
		})
	}
}
