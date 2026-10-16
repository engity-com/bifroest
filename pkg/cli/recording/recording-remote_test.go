package recording

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	bfRecording "github.com/engity-com/bifroest/pkg/recording"
)

func TestRemoteRecordingAuthenticatesRequestedArtifact(t *testing.T) {
	fixture := createRecordingFixture(t)
	clear, err := os.ReadFile(fixture.clear)
	require.NoError(t, err)
	encrypted, err := os.ReadFile(fixture.encrypted)
	require.NoError(t, err)
	otherID, err := bfRecording.NewId()
	require.NoError(t, err)
	var cast bytes.Buffer
	require.NoError(t, doRecordingExport(t.Context(), exportCommandOptions{
		File: fixture.clear, ExpectedProducerID: fixture.identity.ProducerId().String(), Output: "-",
		WithSensitiveOpts: common.WithSensitiveOpts{WithSensitive: true},
	}, &cast))
	app := cli.NewSimpleApplication("test").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })

	for _, artifact := range []struct {
		name    string
		content []byte
		id      bfRecording.Id
		wantErr string
	}{
		{"clear/requested", clear, fixture.id, ""},
		{"clear/substituted", clear, otherID, "requested signed ID"},
		{"encrypted/requested", encrypted, fixture.id, ""},
		{"encrypted/substituted", encrypted, otherID, "requested signed ID"},
		{"cast-instead-of-native", cast.Bytes(), fixture.id, "native sealed Recording"},
	} {
		for _, operation := range []struct {
			name      string
			command   string
			flags     []string
			file      bool
			untrusted bool
		}{
			{"verify", "verify", []string{"--require-full"}, false, false},
			{"export", "export", []string{"--with-sensitive"}, false, false},
			{"export-file", "export", []string{"--with-sensitive", "--force"}, true, false},
			{"play", "play", []string{"--with-sensitive", "--speed=100"}, false, false},
			{"export-untrusted", "export", []string{"--with-sensitive", "--allowUntrusted"}, false, true},
			{"play-untrusted", "play", []string{"--with-sensitive", "--speed=100", "--allowUntrusted"}, false, true},
		} {
			t.Run(artifact.name+"/"+operation.name, func(t *testing.T) {
				target, done := recordingArtifactTestServer(t, artifact.id, fixture.identity.ProducerId().String(), artifact.content)
				args := []string{"recording", operation.command, "default", artifact.id.String(),
					"--decryptionIdentityFile=" + fixture.identityFile,
				}
				if !operation.untrusted {
					args = append(args, "--expectedProducerId="+fixture.identity.ProducerId().String())
				}
				args = append(args, operation.flags...)
				var outputPath string
				if operation.file {
					outputPath = filepath.Join(t.TempDir(), "export.cast")
					require.NoError(t, os.WriteFile(outputPath, []byte("keep-existing-export"), 0600))
					args = append(args, "--output="+outputPath)
				}
				var output bytes.Buffer
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				ctx = common.ContextWithRemoteTarget(ctx, target)
				ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
				err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileRemote}}, args...)
				if artifact.wantErr != "" {
					require.ErrorContains(t, err, artifact.wantErr)
					require.Empty(t, output.String())
					if operation.file {
						unchanged, err := os.ReadFile(outputPath)
						require.NoError(t, err)
						require.Equal(t, "keep-existing-export", string(unchanged))
					}
				} else {
					require.NoError(t, err)
					if operation.file {
						content, err := os.ReadFile(outputPath)
						require.NoError(t, err)
						require.Contains(t, string(content), "sensitive terminal output")
					} else if operation.command == "verify" {
						require.Contains(t, output.String(), "verified (scope: full)")
					} else {
						require.Contains(t, output.String(), "sensitive terminal output")
					}
				}
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal("SSH artifact server did not finish")
				}
			})
		}
	}
}

// The transport header deliberately claims the requested ID independently of
// the signed artifact body, as a compromised but correctly authenticated
// server could do. The header names the actual producer, so pinning it alone
// cannot detect the substitution. SSH host-key verification still applies.
func recordingArtifactTestServer(t *testing.T, requested bfRecording.Id, producer string, content []byte) (management.Target, <-chan error) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	_, hostKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	clientPublicKey, err := ssh.NewPublicKey(publicKey)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(privateKey, "recording-client-test")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientPublicKey.Marshal()) {
			return nil, fmt.Errorf("unrecognized client key")
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
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
			var exec struct{ Command string }
			if request.Type != "exec" || ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != transport.WireRecordingCommand {
				_ = request.Reply(false, nil)
				continue
			}
			if err := request.Reply(true, nil); err != nil {
				done <- err
				return
			}
			args, err := transport.DecodeWireRequest(channel)
			if err != nil || strings.Join(args, " ") != "recording default "+requested.String() {
				done <- fmt.Errorf("unexpected artifact request: %v, %v", args, err)
				return
			}
			digest := sha256.Sum256(content)
			err = transport.WriteRecordingArtifact(channel, transport.RecordingArtifactHeader{
				Version: 1, ID: requested.String(), ProducerID: producer,
				Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
			}, bytes.NewReader(content))
			if err == nil {
				_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}
			done <- err
			return
		}
		done <- fmt.Errorf("missing artifact exec request")
	}()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "identity")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))
	hostsPath := filepath.Join(directory, "known_hosts")
	require.NoError(t, os.WriteFile(hostsPath, []byte(knownhosts.Line(
		[]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(directory, "ssh_config")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(
		"Host recording-id-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityAgent none\n  IdentityFile %s\n  UserKnownHostsFile %s\n",
		listener.Addr().(*net.TCPAddr).Port, filepath.ToSlash(keyPath), filepath.ToSlash(hostsPath))), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	return management.Target{Host: "recording-id-test"}, done
}
