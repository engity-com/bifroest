package version

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/engity-com/bifroest/pkg/management"
)

func TestRemoteVersionForwardsExplicitFormatWithLongServerDefault(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	app := cli.NewSimpleApplication("test").
		WithErrorHandlerEnabled(false).
		WithFallbackToStdio(false).
		WithCommand(CreateCommands(testVersion{})...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	_, hostKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	require.NoError(t, err)
	_, clientKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(clientKey, "version-test")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })
	config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	cases := []struct {
		args    []string
		command string
		long    bool
	}{
		{[]string{"version", "--long=false"}, "version --long=false", false},
		{[]string{"version"}, "version --long=true", true},
		{[]string{"version", "--long=true"}, "version --long=true", true},
		{[]string{"version"}, "version --long=true", true},
	}
	commands := make(chan string, len(cases))
	done := make(chan error, len(cases))
	go func() {
		for range cases {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			done <- serveVersionRequest(t.Context(), conn, config, app, commands)
		}
	}()
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "identity")
	require.NoError(t, os.WriteFile(identityPath, pem.EncodeToMemory(block), 0600))
	hostsPath := filepath.Join(directory, "known_hosts")
	require.NoError(t, os.WriteFile(hostsPath, []byte(knownhosts.Line(
		[]string{knownhosts.Normalize(listener.Addr().String())}, hostSigner.PublicKey())+"\n"), 0600))
	configPath := filepath.Join(directory, "ssh_config")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(
		"Host version-test\n  HostName 127.0.0.1\n  User admin\n  Port %d\n  IdentityAgent none\n  IdentityFile %s\n  UserKnownHostsFile %s\n",
		listener.Addr().(*net.TCPAddr).Port, filepath.ToSlash(identityPath), filepath.ToSlash(hostsPath))), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return configPath })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })

	for _, test := range cases {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		var output bytes.Buffer
		ctx = common.ContextWithRemoteTarget(ctx, management.Target{Host: "version-test"})
		ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
		err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileRemote}}, test.args...)
		cancel()
		require.NoError(t, err)
		require.NoError(t, <-done)
		require.Equal(t, test.command, <-commands)
		if test.long {
			require.Contains(t, output.String(), "Version:  1.2.3")
		} else {
			require.Contains(t, output.String(), "Bifröst 1.2.3")
			require.NotContains(t, output.String(), "Version:")
		}
	}
}

func serveVersionRequest(ctx context.Context, conn net.Conn, config *ssh.ServerConfig, app *cli.Application[cli.NoOptions], commands chan<- string) error {
	defer conn.Close()
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(requests)
	incoming, ok := <-channels
	if !ok {
		return fmt.Errorf("missing version session")
	}
	channel, messages, err := incoming.Accept()
	if err != nil {
		return err
	}
	defer channel.Close()
	for request := range messages {
		var exec struct{ Command string }
		if request.Type != "exec" || ssh.Unmarshal(request.Payload, &exec) != nil {
			_ = request.Reply(false, nil)
			continue
		}
		commands <- exec.Command
		if err := request.Reply(true, nil); err != nil {
			return err
		}
		serverContext := cli.ContextWithStdio(ctx, nil, channel, channel.Stderr())
		if err := app.ParseAndExecute(serverContext, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, strings.Fields(exec.Command)...); err != nil {
			return err
		}
		_, err := channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		if err != nil {
			return err
		}
		if err := channel.Close(); err != nil {
			return err
		}
		// Match the integrated management fixtures: let the client consume its
		// exit status and close the transport before TCP teardown, which can
		// otherwise discard status/window messages still in flight on Windows.
		_ = server.Wait()
		return nil
	}
	return fmt.Errorf("missing version exec request")
}
