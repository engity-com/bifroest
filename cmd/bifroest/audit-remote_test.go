package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestRemoteAuditExportDecryptsLocallyFromSignedSnapshot(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	directory := t.TempDir()
	encryption := newRecordingExportTestFixture(t)
	private, err := loadAuditPrivateKey(encryption.identityPath)
	require.NoError(t, err)
	public := bfcrypto.PublicKeys(strings.TrimSpace(string(bfcrypto.MarshalPublicKey(private.PublicKey()))))
	configured := createAuditCliTestJournalWithEncryption(t, directory, "default", "test.remote-audit", public)
	expected := auditCliTestProducerId(t, configured.IdentityFile)
	source, err := configuredAuditJournalSource(&configured, nil, expected)
	require.NoError(t, err)
	snapshot, err := management.SnapshotAudit(t.Context(), source)
	require.NoError(t, err)
	defer func() { require.NoError(t, snapshot.Close()) }()
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
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
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
			if ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != management.WireAuditCommand {
				done <- fmt.Errorf("unexpected command")
				return
			}
			if err := request.Reply(true, nil); err != nil {
				done <- err
				return
			}
			args, err := management.DecodeWireRequest(channel)
			if err != nil || strings.Join(args, " ") != "auditlog default" {
				done <- fmt.Errorf("unexpected audit request: %v, %v", args, err)
				return
			}
			err = snapshot.WriteTo(channel)
			if err == nil {
				_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}
			done <- err
			return
		}
		done <- fmt.Errorf("missing exec request")
	}()
	keyFile := filepath.Join(directory, "client-key")
	require.NoError(t, goos.WriteFile(keyFile, pem.EncodeToMemory(block), 0600))
	hosts := filepath.Join(directory, "known_hosts")
	require.NoError(t, goos.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(directory, "ssh-config")
	sshConfig := fmt.Sprintf("IgnoreUnknown X-*\nHost audit-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityFile %s\n  UserKnownHostsFile %s\n  X-AuditPrivateKey %s\n  X-ExpectedProducerId %s\n", listener.Addr().(*net.TCPAddr).Port, keyFile, hosts, encryption.identityPath, expected)
	require.NoError(t, goos.WriteFile(configPath, []byte(sshConfig), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	defer func() { ssh_config.DefaultUserSettings = previous }()
	prior := remoteAuditExportOpts
	defer func() { remoteAuditExportOpts = prior }()
	registerAuditExportCmd(kingpin.New("bifroest", "test").Command("audit", "test"))
	remoteAuditExportOpts.auditlog = "default"
	remoteAuditExportOpts.withSensitive = true
	var output bytes.Buffer
	require.NoError(t, doRemoteAuditCommand(context.Background(), &managementTarget{RawHost: "audit-test", Port: 22}, "audit export", &output))
	require.Contains(t, output.String(), "confidential-flow-default")
	require.NoError(t, <-done)
}
