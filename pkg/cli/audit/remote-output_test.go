package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestRemoteAuditRevalidatesSSHInputsAfterDownload(t *testing.T) {
	for command, operation := range map[string]remoteAuditOperation{"export": remoteExport, "merge": remoteMerge} {
		for _, input := range []string{"SSH login identity", "SSH known-hosts file", "SSH client configuration"} {
			for _, alias := range []string{"symlink", "hardlink"} {
				t.Run(fmt.Sprintf("%s/%s/%s", command, input, alias), func(t *testing.T) {
					link := os.Link
					if alias == "symlink" {
						link = os.Symlink
					}
					// Check filesystem support before starting the SSH test server.
					probeRoot := t.TempDir()
					probe := filepath.Join(probeRoot, "source")
					require.NoError(t, os.WriteFile(probe, []byte("probe"), 0600))
					if err := link(probe, filepath.Join(probeRoot, "alias")); err != nil {
						t.Skipf("%s unavailable: %v", alias, err)
					}
					outputRoot := canonicalTestTempDir(t)
					output := filepath.Join(outputRoot, "audit.jsonl")
					server := newRemoteAuditOutputTestServer(t, func(inputs map[string]string) error {
						// The initial guard saw a missing, unprotected output. Change
						// it only after the client has started its snapshot download.
						return link(inputs[input], output)
					})
					before := make(map[string][]byte, len(server.inputs))
					for name, path := range server.inputs {
						var err error
						before[name], err = os.ReadFile(path)
						require.NoError(t, err)
					}
					stdout, err := server.run(t, operation, output, true)
					require.ErrorContains(t, err, "must not replace "+input)
					require.Empty(t, stdout)
					for name, path := range server.inputs {
						requireAuditCliTestFileUnchanged(t, path, before[name])
					}
					requireAuditCliTestFileUnchanged(t, output, before[input])
					entries, err := os.ReadDir(outputRoot)
					require.NoError(t, err)
					require.Len(t, entries, 1, "rejected export must not leave temporary files")
				})
			}
		}
	}
}

func TestRemoteAuditExportsToUnprotectedFiles(t *testing.T) {
	for command, operation := range map[string]remoteAuditOperation{"export": remoteExport, "merge": remoteMerge} {
		for _, force := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/force=%t", command, force), func(t *testing.T) {
				server := newRemoteAuditOutputTestServer(t, nil)
				outputRoot := canonicalTestTempDir(t)
				output := filepath.Join(outputRoot, "audit.jsonl")
				if force {
					require.NoError(t, os.WriteFile(output, []byte("existing output\n"), 0600))
				}
				stdout, err := server.run(t, operation, output, force)
				require.NoError(t, err)
				require.Empty(t, stdout)
				raw, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Contains(t, string(raw), `"name":"test.remote-output"`)
				info, err := os.Stat(output)
				require.NoError(t, err)
				requireAuditOutputPrivate(t, output, info)
				entries, err := os.ReadDir(outputRoot)
				require.NoError(t, err)
				require.Len(t, entries, 1)
			})
		}
	}
}

type remoteAuditOutputTestServer struct {
	target   management.Target
	producer string
	inputs   map[string]string
	done     <-chan error
}

func (this remoteAuditOutputTestServer) run(t *testing.T, operation remoteAuditOperation, path string, force bool) ([]byte, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(cli.ContextWithStdio(t.Context(), nil, &stdout, &stderr), 10*time.Second)
	defer cancel()
	err := runRemoteAudit(ctx, this.target, remoteAuditOptions{
		Operation: operation, Names: []configuration.AuditlogName{"default"}, TrustAnchors: []string{this.producer},
		Output: path, Force: force, Format: format.Text,
	}, &stdout)
	select {
	case serverErr := <-this.done:
		require.NoError(t, serverErr)
	case <-ctx.Done():
		t.Fatalf("SSH snapshot server did not complete: %v (client: %v)", ctx.Err(), err)
	}
	return stdout.Bytes(), err
}

func newRemoteAuditOutputTestServer(t *testing.T, beforeSnapshot func(map[string]string) error) remoteAuditOutputTestServer {
	t.Helper()
	root := canonicalTestTempDir(t)
	privateRoot := filepath.Join(root, "private")
	require.NoError(t, os.Mkdir(privateRoot, 0700))
	configured := createAuditCliTestJournal(t, root, "default", "test.remote-output")
	producer := auditCliTestProducerId(t, configured.IdentityFile)
	source, err := configuredAuditJournalSource(&configured, nil, producer)
	require.NoError(t, err)
	snapshot, err := transport.SnapshotAudit(t.Context(), source)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, snapshot.Close()) })
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	host, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	identity, _ := createAuditCliTestKeyPair(t, privateRoot, "login-key")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	hosts := filepath.Join(privateRoot, "known_hosts")
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, host.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(privateRoot, "ssh-config")
	raw := fmt.Sprintf("Host audit-output\n HostName 127.0.0.1\n User admin\n Port %d\n IdentityAgent none\n IdentityFile %q\n UserKnownHostsFile %q\n",
		listener.Addr().(*net.TCPAddr).Port, filepath.ToSlash(identity), filepath.ToSlash(hosts))
	require.NoError(t, os.WriteFile(configPath, []byte(raw), 0600))
	inputs := map[string]string{
		"SSH login identity": identity, "SSH known-hosts file": hosts, "SSH client configuration": configPath,
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			done <- err
			return
		}
		config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
		config.AddHostKey(host)
		_, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			done <- err
			return
		}
		go ssh.DiscardRequests(requests)
		incoming, ok := <-channels
		if !ok {
			done <- fmt.Errorf("missing SSH session")
			return
		}
		channel, messages, err := incoming.Accept()
		if err != nil {
			done <- err
			return
		}
		defer channel.Close()
		for request := range messages {
			if request.Type != "exec" {
				_ = request.Reply(false, nil)
				continue
			}
			var exec struct{ Command string }
			if ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != transport.WireAuditCommand {
				done <- fmt.Errorf("unexpected SSH command")
				return
			}
			if err := request.Reply(true, nil); err != nil {
				done <- err
				return
			}
			args, err := transport.DecodeWireRequest(channel)
			if err != nil || strings.Join(args, " ") != "auditlog default" {
				done <- fmt.Errorf("unexpected audit request: %v, %v", args, err)
				return
			}
			if beforeSnapshot != nil {
				if err := beforeSnapshot(inputs); err != nil {
					done <- err
					return
				}
			}
			err = snapshot.StreamTo(channel)
			if err == nil {
				_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}
			done <- err
			return
		}
		done <- io.EOF
	}()
	return remoteAuditOutputTestServer{
		target:   management.Target{Host: "audit-output", SSHConfigFile: configPath},
		producer: producer.String(), inputs: inputs, done: done,
	}
}
