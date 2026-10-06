package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"net"
	goos "os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestRemoteRecordingExportDecryptsOnClient(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	fixture := newRecordingExportTestFixture(t)
	content, err := goos.ReadFile(fixture.nativeEncryptedPath)
	require.NoError(t, err)
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	_, clientKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(clientKey, "test")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	serverConfig.AddHostKey(hostSigner)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			done <- err
			return
		}
		go ssh.DiscardRequests(requests)
		incoming := <-channels
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
			if ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != management.WireRecordingCommand {
				done <- fmt.Errorf("unexpected command")
				return
			}
			if err := request.Reply(true, nil); err != nil {
				done <- err
				return
			}
			args, err := management.DecodeWireRequest(channel)
			if err != nil || strings.Join(args, " ") != "recording default "+fixture.recordingId.String() {
				done <- fmt.Errorf("unexpected request: %v, %v", args, err)
				return
			}
			digest := sha256.Sum256(content)
			err = management.WriteRecordingArtifact(channel, management.RecordingArtifactHeader{
				Version: 1, ID: fixture.recordingId.String(), ProducerID: fixture.identity.ProducerId().String(), Size: int64(len(content)), SHA256: fmt.Sprintf("%x", digest),
			}, bytes.NewReader(content))
			if err == nil {
				_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}
			done <- err
			return
		}
		done <- fmt.Errorf("missing exec request")
	}()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "identity")
	require.NoError(t, goos.WriteFile(keyPath, pem.EncodeToMemory(block), 0600))
	hostsPath := filepath.Join(directory, "known_hosts")
	require.NoError(t, goos.WriteFile(hostsPath, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(directory, "config")
	config := fmt.Sprintf("IgnoreUnknown X-*\nHost recording-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityFile %s\n  UserKnownHostsFile %s\n  X-RecordingPrivateKey %s\n  X-ExpectedProducerId %s\n", listener.Addr().(*net.TCPAddr).Port, keyPath, hostsPath, fixture.identityPath, fixture.identity.ProducerId())
	require.NoError(t, goos.WriteFile(configPath, []byte(config), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	defer func() { ssh_config.DefaultUserSettings = previous }()
	prior := remoteRecordingExportOpts
	defer func() { remoteRecordingExportOpts = prior }()
	registerRecordingExportCmd(kingpin.New("bifroest", "test").Command("recording", "test"))
	remoteRecordingExportOpts.file = "default"
	remoteRecordingExportOpts.recordingId = fixture.recordingId.String()
	remoteRecordingExportOpts.withSensitive = true
	var output bytes.Buffer
	require.NoError(t, doRemoteRecordingCommand(context.Background(), &managementTarget{RawHost: "recording-test", Port: 22}, "recording export", &output))
	require.Contains(t, output.String(), "sensitive terminal output")
	require.NoError(t, <-done)
}
