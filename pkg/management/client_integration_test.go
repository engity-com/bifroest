package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	cliformat "github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/recording"
)

func TestManagementClientExecsCBORAndRendersJSON(t *testing.T) {
	target, serverDone := managementClientTestServer(t, transport.WireCommand, func(channel ssh.Channel, args []string) error {
		if strings.Join(args, " ") != "flow ls" {
			return fmt.Errorf("unexpected request args %v", args)
		}
		if err := cliformat.WriteFlowList(channel, cliformat.WireCbor, []model.FlowSummary{{Name: "production", Auditlog: "default"}}); err != nil {
			return err
		}
		_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return err
	})
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
	require.NoError(t, target.Run(ctx, "flow", "ls", "--format=json"))
	var entries []model.FlowSummary
	require.NoError(t, json.Unmarshal(output.Bytes(), &entries))
	require.Len(t, entries, 1)
	require.Equal(t, "production", entries[0].Name.String())
	require.NoError(t, <-serverDone)
}

func TestManagementRecordingStreamRejectsTruncationAndPreservesVerifiedPrefix(t *testing.T) {
	target, done := managementClientTestServer(t, transport.WireRecordingListStreamCommand, func(channel ssh.Channel, args []string) error {
		if strings.Join(args, " ") != "recording ls default" {
			return fmt.Errorf("unexpected streaming request %v", args)
		}
		if err := transport.WriteRecordingStreamEntry(channel, model.RecordingView{ID: "verified-prefix"}); err != nil {
			return err
		}
		if _, err := io.WriteString(channel.Stderr(), "server stream stopped early\n"); err != nil {
			return err
		}
		_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
	err := target.Run(ctx, "recording", "ls", "default", "--format=json")
	require.ErrorContains(t, err, "completion frame")
	require.Contains(t, output.String(), "verified-prefix")
	require.False(t, json.Valid(output.Bytes()))
	require.NoError(t, <-done)
}

type failedRecordingStreamOutput struct{}

func (failedRecordingStreamOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestManagementRecordingStreamAbortsProducerOnLocalOutputFailure(t *testing.T) {
	target, done := managementClientTestServer(t, transport.WireRecordingListStreamCommand, func(channel ssh.Channel, _ []string) error {
		for {
			if err := transport.WriteRecordingStreamEntry(channel, model.RecordingView{ID: "entry"}); err != nil {
				return nil
			}
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = cli.ContextWithStdio(ctx, nil, failedRecordingStreamOutput{}, nil)
	require.ErrorIs(t, target.Run(ctx, "recording", "ls", "default", "--format=json"), io.ErrClosedPipe)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("stream producer did not stop after a client output error")
	}
}

func TestManagementArtifactFailuresReadDiagnosticsBeforeServerExit(t *testing.T) {
	id, err := recording.NewId()
	require.NoError(t, err)
	for _, test := range []struct {
		name     string
		command  string
		args     []string
		download func(context.Context, Target, string) error
		wantErr  string
	}{
		{"recording", transport.WireRecordingCommand, []string{"recording", "default", id.String()},
			func(ctx context.Context, target Target, _ string) error {
				_, err := DownloadRecording(ctx, target, "default", id.String(), io.Discard)
				return err
			}, "invalid Recording artifact header length"},
		{"audit", transport.WireAuditCommand, []string{"auditlog", "default"},
			func(ctx context.Context, target Target, root string) error {
				_, err := DownloadAuditSnapshot(ctx, target, "default", root)
				return err
			}, "invalid audit snapshot header length"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, serverDone := managementClientTestServer(t, test.command, func(channel ssh.Channel, args []string) error {
				if strings.Join(args, " ") != strings.Join(test.args, " ") {
					return fmt.Errorf("unexpected artifact request args %v", args)
				}
				// Exceed the SSH window so diagnostics must be consumed before the bad header arrives.
				if _, err := channel.Stderr().Write(bytes.Repeat([]byte("transfer diagnostic\n"), 256<<10)); err != nil {
					return err
				}
				if _, err := channel.Write([]byte{0, 0, 0, 0}); err != nil {
					return err
				}
				// Keep stderr active without an exit status until the client rejects the artifact.
				for {
					if _, err := io.WriteString(channel.Stderr(), "still running\n"); err != nil {
						return nil
					}
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := test.download(ctx, target, t.TempDir())
			require.ErrorContains(t, err, test.wantErr)
			require.ErrorContains(t, err, "transfer diagnostic")
			require.LessOrEqual(t, len(err.Error()), (16<<10)+256)
			require.NoError(t, ctx.Err(), "download must fail without waiting for the server to exit")
			select {
			case err := <-serverDone:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("SSH artifact server did not finish")
			}
		})
	}
}

func managementClientTestServer(t *testing.T, command string, handle func(ssh.Channel, []string) error) (Target, <-chan error) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	identityBlock, err := ssh.MarshalPrivateKey(identity, "test")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	port := listener.Addr().(*net.TCPAddr).Port
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(key.Marshal(), hostSigner.PublicKey().Marshal()) {
			return nil, fmt.Errorf("host key cannot authenticate")
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			serverDone <- err
			return
		}
		go ssh.DiscardRequests(requests)
		incoming := <-channels
		channel, messages, err := incoming.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer channel.Close()
		for request := range messages {
			if request.Type != "exec" {
				_ = request.Reply(false, nil)
				continue
			}
			var exec struct{ Command string }
			if ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != command {
				_ = request.Reply(false, nil)
				serverDone <- fmt.Errorf("unexpected SSH exec command")
				return
			}
			if err := request.Reply(true, nil); err != nil {
				serverDone <- err
				return
			}
			args, err := transport.DecodeWireRequest(channel)
			if err != nil {
				serverDone <- err
				return
			}
			serverDone <- handle(channel, args)
			return
		}
		serverDone <- fmt.Errorf("missing SSH exec request")
	}()
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "identity")
	require.NoError(t, os.WriteFile(identityPath, pem.EncodeToMemory(identityBlock), 0600))
	hosts := filepath.Join(directory, "known_hosts")
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(directory, "config")
	contents := fmt.Sprintf("Host management-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityAgent none\n  IdentityFile %s\n  UserKnownHostsFile %s\n", port, filepath.ToSlash(identityPath), filepath.ToSlash(hosts))
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	return Target{Host: "management-test", Port: 22}, serverDone
}
