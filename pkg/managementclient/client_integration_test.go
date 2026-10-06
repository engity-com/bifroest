package managementclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementClientExecsCBORAndRendersJSON(t *testing.T) {
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
	defer listener.Close()
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
			if ssh.Unmarshal(request.Payload, &exec) != nil || exec.Command != management.WireCommand {
				_ = request.Reply(false, nil)
				serverDone <- fmt.Errorf("unexpected SSH exec command")
				return
			}
			if err := request.Reply(true, nil); err != nil {
				serverDone <- err
				return
			}
			args, err := management.DecodeWireRequest(channel)
			if err != nil {
				serverDone <- err
				return
			}
			if strings.Join(args, " ") != "flow ls" {
				serverDone <- fmt.Errorf("unexpected request args %v", args)
				return
			}
			if err := management.WriteFlowList(channel, management.FormatCBOR, []management.FlowSummary{{Name: "production", Auditlog: "default"}}); err != nil {
				serverDone <- err
				return
			}
			_, err = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			serverDone <- err
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
	contents := fmt.Sprintf("Host management-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityFile %s\n  UserKnownHostsFile %s\n", port, identityPath, hosts)
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	defer func() { ssh_config.DefaultUserSettings = previous }()
	var output bytes.Buffer
	require.NoError(t, Run(context.Background(), Target{Host: "management-test", Port: 22}, []string{"flow", "ls", "--format=json"}, &output))
	var entries []management.FlowSummary
	require.NoError(t, json.Unmarshal(output.Bytes(), &entries))
	require.Len(t, entries, 1)
	require.Equal(t, "production", entries[0].Name.String())
	require.NoError(t, <-serverDone)
}
