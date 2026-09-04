package service

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	glssh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestRestrictedAuthorizedKeyEnforcesForcedCommand(t *testing.T) {
	const (
		forcedCommand    = "forced-command"
		requestedCommand = "client-supplied-command"
	)

	env := &authorizedKeysTestEnvironment{
		run: func(task environment.Task) (int, error) {
			_, err := fmt.Fprintf(task.SshSession(), "%s|%s", task.SshSession().RawCommand(), findEnvironmentValue(task.SshSession().Environ(), "SSH_ORIGINAL_COMMAND"))
			return 0, err
		},
	}
	server := newAuthorizedKeysTestServer(t, `command="`+forcedCommand+`"`, env)
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	output, err := sshSession.Output(requestedCommand)
	require.NoError(t, err)
	require.Equal(t, forcedCommand+"|"+requestedCommand, string(output))
}

func TestRestrictedAuthorizedKeyAddsEnvironmentVariables(t *testing.T) {
	env := &authorizedKeysTestEnvironment{
		run: func(task environment.Task) (int, error) {
			_, err := fmt.Fprintf(task.SshSession(), "%s|%s",
				findEnvironmentValue(task.SshSession().Environ(), "FROM_AUTHORIZED_KEY"),
				findEnvironmentValue(task.SshSession().Environ(), "SECOND_FROM_AUTHORIZED_KEY"))
			return 0, err
		},
	}
	server := newAuthorizedKeysTestServer(t, `environment="FROM_AUTHORIZED_KEY=server",environment="SECOND_FROM_AUTHORIZED_KEY=second"`, env)
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Setenv("FROM_AUTHORIZED_KEY", "client"))
	output, err := sshSession.Output("print-environment")
	require.NoError(t, err)
	require.Equal(t, "server|second", string(output))
}

func TestRestrictedAuthorizedKeyRejectsAuthenticationConditions(t *testing.T) {
	cases := map[string]string{
		"source-address":     `from="192.0.2.0/24"`,
		"expired-key":        `expiry-time="20000101"`,
		"unsupported-option": "no-touch-required",
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{})
			client, err := server.dial()
			if client != nil {
				_ = client.Close()
			}
			require.Error(t, err)
		})
	}
}

func TestRestrictedAuthorizedKeyAllowsAuthenticationConditions(t *testing.T) {
	for name, options := range map[string]string{
		"source-address": `from="127.0.0.1"`,
		"future-expiry":  `expiry-time="29991231"`,
	} {
		t.Run(name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{})
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.NoError(t, sshSession.Run("allowed"))
		})
	}
}

func TestRestrictedAuthorizedKeyRejectsPty(t *testing.T) {
	for _, options := range []string{"no-pty", "restrict"} {
		t.Run(options, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{})
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			err = sshSession.RequestPty("xterm", 24, 80, gossh.TerminalModes{})
			require.Error(t, err)
		})
	}
}

func TestRestrictedAuthorizedKeyCanReenablePty(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "restrict,pty", &authorizedKeysTestEnvironment{})
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.RequestPty("xterm", 24, 80, gossh.TerminalModes{}))
}

func TestMaxSessionsPerConnectionIsEnforced(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxSessionsPerConnection = 1
		conf.Ssh.MaxChannelsPerConnection = 10
		conf.Ssh.MaxChannels = 10
	})
	client := server.mustDial(t)
	first, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	second, err := client.NewSession()
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
}

func TestMaxChannelsPerConnectionIsEnforced(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxSessionsPerConnection = 10
		conf.Ssh.MaxChannelsPerConnection = 1
		conf.Ssh.MaxChannels = 10
	})
	client := server.mustDial(t)
	first, err := client.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	second, err := client.NewSession()
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
}

func TestMaxChannelsAcrossConnectionsIsEnforced(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxSessionsPerConnection = 10
		conf.Ssh.MaxChannelsPerConnection = 10
		conf.Ssh.MaxChannels = 1
	})
	firstClient := server.mustDial(t)
	firstSession, err := firstClient.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = firstSession.Close() })

	secondClient := server.mustDial(t)
	secondSession, err := secondClient.NewSession()
	if secondSession != nil {
		_ = secondSession.Close()
	}
	require.Error(t, err)
}

func TestDisabledMaxChannelsAllowsChannelsAcrossConnections(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxSessionsPerConnection = 10
		conf.Ssh.MaxChannelsPerConnection = 10
		conf.Ssh.MaxChannels = 0
	})
	firstClient := server.mustDial(t)
	firstSession, err := firstClient.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = firstSession.Close() })

	secondClient := server.mustDial(t)
	secondSession, err := secondClient.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() { _ = secondSession.Close() })
}

func TestSessionRequestTimeoutClosesIdleSession(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.SessionRequestTimeout = common.DurationOf(100 * time.Millisecond)
	})
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- sshSession.Wait() }()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("idle SSH session was not closed after sessionRequestTimeout")
	}
}

func TestRestrictedAuthorizedKeyRejectsAgentForwarding(t *testing.T) {
	for _, options := range []string{"no-agent-forwarding", "restrict"} {
		t.Run(options, func(t *testing.T) {
			testEnvironment := &authorizedKeysTestEnvironment{
				run: func(task environment.Task) (int, error) {
					allowed := bssh.AgentRequested(task.SshSession()) && authorization.IsAgentForwardingAllowed(task.Authorization())
					_, err := fmt.Fprint(task.SshSession(), allowed)
					return 0, err
				},
			}
			server := newAuthorizedKeysTestServer(t, options, testEnvironment)
			client := server.mustDial(t)
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			require.Error(t, agent.RequestAgentForwarding(sshSession))
			output, err := sshSession.Output("check-agent-forwarding")
			require.NoError(t, err)
			require.Equal(t, "false", string(output))
		})
	}
}

func TestRestrictedAuthorizedKeyCanReenableAgentForwarding(t *testing.T) {
	testEnvironment := &authorizedKeysTestEnvironment{
		run: func(task environment.Task) (int, error) {
			allowed := bssh.AgentRequested(task.SshSession()) && authorization.IsAgentForwardingAllowed(task.Authorization())
			_, err := fmt.Fprint(task.SshSession(), allowed)
			return 0, err
		},
	}
	server := newAuthorizedKeysTestServer(t, "restrict,agent-forwarding", testEnvironment)
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, agent.RequestAgentForwarding(sshSession))
	output, err := sshSession.Output("check-agent-forwarding")
	require.NoError(t, err)
	require.Equal(t, "true", string(output))
}

func TestRestrictedAuthorizedKeyRejectsDirectPortForwarding(t *testing.T) {
	cases := map[string]string{
		"disabled":          "no-port-forwarding",
		"restrict":          "restrict",
		"destination-limit": `permitopen="example.com:22"`,
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{portForwardingAllowed: true})
			client := server.mustDial(t)
			conn, err := client.Dial("tcp", "example.net:2222")
			if conn != nil {
				_ = conn.Close()
			}
			require.Error(t, err)
		})
	}
}

func TestRestrictedAuthorizedKeyAllowsPermittedDirectPortForwarding(t *testing.T) {
	for _, options := range []string{`permitopen="example.net:2222"`, "restrict,port-forwarding"} {
		t.Run(options, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{portForwardingAllowed: true})
			client := server.mustDial(t)
			conn, err := client.Dial("tcp", "example.net:2222")
			require.NoError(t, err)
			require.NoError(t, conn.Close())
		})
	}
}

func TestRestrictedAuthorizedKeyRejectsReversePortForwarding(t *testing.T) {
	cases := map[string]string{
		"disabled":     "no-port-forwarding",
		"restrict":     "restrict",
		"listen-limit": `permitlisten="127.0.0.1:2222"`,
	}
	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, options, &authorizedKeysTestEnvironment{portForwardingAllowed: true})
			client := server.mustDial(t)
			listener, err := client.Listen("tcp", "127.0.0.1:0")
			if listener != nil {
				_ = listener.Close()
			}
			require.Error(t, err)
		})
	}
}

func TestRestrictedAuthorizedKeyAllowsPermittedReversePortForwarding(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, `permitlisten="127.0.0.1:*"`, &authorizedKeysTestEnvironment{portForwardingAllowed: true})
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, listener.Close())
}

func TestEnvironmentRejectsReversePortForwarding(t *testing.T) {
	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{portForwardingAllowed: false})
	client := server.mustDial(t)
	listener, err := client.Listen("tcp", "127.0.0.1:0")
	if listener != nil {
		_ = listener.Close()
	}
	require.Error(t, err)
}

func TestMaxReverseForwardsPerConnectionIsEnforced(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{portForwardingAllowed: true}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxReverseForwardsPerConnection = 1
		conf.Ssh.MaxReverseForwards = 10
	})
	client := server.mustDial(t)
	first, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	second, err := client.Listen("tcp", "127.0.0.1:0")
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
}

func TestMaxReverseForwardsAcrossConnectionsIsEnforced(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{portForwardingAllowed: true}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxReverseForwardsPerConnection = 10
		conf.Ssh.MaxReverseForwards = 1
	})
	firstClient := server.mustDial(t)
	first, err := firstClient.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	secondClient := server.mustDial(t)
	second, err := secondClient.Listen("tcp", "127.0.0.1:0")
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
}

func TestHandshakeTimeoutClosesUnauthenticatedConnection(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.HandshakeTimeout = common.DurationOf(500 * time.Millisecond)
	})
	conn, err := gonet.Dial("tcp", server.address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	reader := bufio.NewReader(conn)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	banner, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(banner, "SSH-2.0-Engity-Bifroest_"))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err = reader.ReadByte()
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, "the connection must remain open before the server-side handshake timeout")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = reader.ReadByte()
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the server-side handshake timeout must close the connection")
}

func TestMaxStartupsDropsExcessUnauthenticatedConnection(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxStartupsStart = 2
		conf.Ssh.MaxStartupsRate = 0
		conf.Ssh.MaxStartupsFull = 2
	})
	first, err := gonet.Dial("tcp", server.address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })
	require.NoError(t, first.SetReadDeadline(time.Now().Add(time.Second)))
	banner, err := bufio.NewReader(first).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(banner, "SSH-2.0-Engity-Bifroest_"))

	second, err := gonet.Dial("tcp", server.address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })
	require.NoError(t, second.SetReadDeadline(time.Now().Add(time.Second)))
	banner, err = bufio.NewReader(second).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(banner, "SSH-2.0-Engity-Bifroest_"))

	third, err := gonet.Dial("tcp", server.address)
	require.NoError(t, err)
	t.Cleanup(func() { _ = third.Close() })
	require.NoError(t, third.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = third.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestConnectionLifecycleWaitsForSessionHandlerDuringGracefulShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHandler)
	testEnvironment := &authorizedKeysTestEnvironment{
		run: func(environment.Task) (int, error) {
			close(started)
			<-release
			return 0, nil
		},
	}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		conf.Ssh.GracefulShutdownTimeout = common.DurationOf(500 * time.Millisecond)
	})
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	runDone := make(chan error, 1)
	go func() { runDone <- sshSession.Run("block") }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SSH session handler did not start")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- server.stop() }()
	select {
	case err := <-stopDone:
		t.Fatalf("service resources closed before the session handler ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	releaseHandler()
	require.NoError(t, client.Close())
	select {
	case err := <-stopDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("service did not finish after the session handler ended")
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("SSH client session did not finish")
	}
}

func TestConnectionLifecycleDrainsSessionHandlerAfterForcedShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseHandler)
	testEnvironment := &authorizedKeysTestEnvironment{
		run: func(environment.Task) (int, error) {
			close(started)
			<-release
			return 0, nil
		},
	}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		conf.Ssh.GracefulShutdownTimeout = common.DurationOf(50 * time.Millisecond)
	})
	client := server.mustDial(t)
	sshSession, err := client.NewSession()
	require.NoError(t, err)
	runDone := make(chan error, 1)
	go func() { runDone <- sshSession.Run("block") }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("SSH session handler did not start")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- server.stop() }()
	select {
	case err := <-stopDone:
		t.Fatalf("service resources closed before the forced session handler ended: %v", err)
	case <-time.After(70 * time.Millisecond):
	}

	releaseHandler()
	select {
	case err := <-stopDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("service did not finish after the forced session handler ended")
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("SSH client session did not finish")
	}
}

type authorizedKeysTestServer struct {
	address     string
	username    string
	signer      gossh.Signer
	service     *service
	cancelServe context.CancelFunc
	serveDone   <-chan error
	stopOnce    sync.Once
	stopped     chan struct{}
	stopErr     error
}

func newAuthorizedKeysTestServer(t *testing.T, options string, testEnvironment *authorizedKeysTestEnvironment) *authorizedKeysTestServer {
	return newAuthorizedKeysTestServerWithConfiguration(t, options, testEnvironment, nil)
}

func newAuthorizedKeysTestServerWithConfiguration(t *testing.T, options string, testEnvironment *authorizedKeysTestEnvironment, configure func(*configuration.Configuration)) *authorizedKeysTestServer {
	t.Helper()
	const username = "restricted-key-user"

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	publicKey := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	if options != "" {
		publicKey = options + " " + publicKey
	}

	tempDir := t.TempDir()
	var conf configuration.Configuration
	err = conf.LoadFromYaml(strings.NewReader(fmt.Sprintf(`
ssh:
  addresses: ["127.0.0.1:0"]
  keys:
    hostKeys: ["%s"]
  banner: ""
session:
  type: fs
  storage: "%s"
flows:
  - name: restricted-key
    requirement:
      includedRequestingName: "^%s$"
    authorization:
      type: simple
      entries:
        - name: %s
          authorizedKeys: |
            %s
    environment:
      type: dummy
`, filepath.ToSlash(filepath.Join(tempDir, "host-key")), filepath.ToSlash(filepath.Join(tempDir, "sessions")), username, username, publicKey)), "authorized-keys-restrictions-test.yaml")
	require.NoError(t, err)
	if configure != nil {
		configure(&conf)
	}

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.NoError(t, svc.environments.Close())
	svc.environments = &authorizedKeysTestRepository{environment: testEnvironment}

	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	serveCtx, cancelServe := context.WithCancel(context.Background())
	go func() {
		serveDone <- svc.server.Serve(serveCtx, listener)
	}()
	result := &authorizedKeysTestServer{
		address:     listener.Addr().String(),
		username:    username,
		signer:      signer,
		service:     svc,
		cancelServe: cancelServe,
		serveDone:   serveDone,
		stopped:     make(chan struct{}),
	}
	t.Cleanup(func() { require.NoError(t, result.stop()) })
	return result
}

func (this *authorizedKeysTestServer) stop() error {
	this.stopOnce.Do(func() {
		defer close(this.stopped)
		gracefulShutdownTimeout := this.service.Configuration.Ssh.GracefulShutdownTimeout.Native()
		this.service.connectionLifecycle.stop()
		this.cancelServe()
		select {
		case <-this.serveDone:
		case <-time.After(5 * time.Second):
			this.stopErr = fmt.Errorf("SSH server did not stop")
			return
		}
		if !this.service.connectionLifecycle.wait(gracefulShutdownTimeout) {
			this.stopErr = fmt.Errorf("SSH connection handlers did not stop")
			return
		}
		this.stopErr = this.service.Close()
	})
	<-this.stopped
	return this.stopErr
}

func (this *authorizedKeysTestServer) dial() (*gossh.Client, error) {
	return gossh.Dial("tcp", this.address, &gossh.ClientConfig{
		User:            this.username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(this.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
		Timeout:         5 * time.Second,
	})
}

func (this *authorizedKeysTestServer) mustDial(t *testing.T) *gossh.Client {
	t.Helper()
	client, err := this.dial()
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type authorizedKeysTestRepository struct {
	environment *authorizedKeysTestEnvironment
}

func (*authorizedKeysTestRepository) WillBeAccepted(environment.Context) (bool, error) {
	return true, nil
}

func (*authorizedKeysTestRepository) DoesSupportPty(environment.Context, glssh.Pty) (bool, error) {
	return true, nil
}

func (this *authorizedKeysTestRepository) Ensure(environment.Request) (environment.Environment, error) {
	return this.environment, nil
}

func (*authorizedKeysTestRepository) FindBySession(context.Context, session.Session, *environment.FindOpts) (environment.Environment, error) {
	return nil, environment.ErrNoSuchEnvironment
}

func (*authorizedKeysTestRepository) Cleanup(context.Context, *environment.CleanupOpts) error {
	return nil
}

func (*authorizedKeysTestRepository) Close() error {
	return nil
}

type authorizedKeysTestEnvironment struct {
	run                   func(environment.Task) (int, error)
	portForwardingAllowed bool
}

func (*authorizedKeysTestEnvironment) Banner(environment.Request) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (this *authorizedKeysTestEnvironment) Run(task environment.Task) (int, error) {
	if this.run != nil {
		return this.run(task)
	}
	return 0, nil
}

func (this *authorizedKeysTestEnvironment) IsPortForwardingAllowed(bnet.HostPort) (bool, error) {
	return this.portForwardingAllowed, nil
}

func (*authorizedKeysTestEnvironment) NewDestinationConnection(context.Context, bnet.HostPort) (io.ReadWriteCloser, error) {
	server, peer := gonet.Pipe()
	go func() {
		defer func() { _ = peer.Close() }()
		_, _ = io.Copy(io.Discard, peer)
	}()
	return server, nil
}

func (*authorizedKeysTestEnvironment) Dispose(context.Context) (bool, error) {
	return false, nil
}

func (*authorizedKeysTestEnvironment) Close() error {
	return nil
}

func findEnvironmentValue(values []string, name string) string {
	prefix := name + "="
	for i := len(values) - 1; i >= 0; i-- {
		if strings.HasPrefix(values[i], prefix) {
			return strings.TrimPrefix(values[i], prefix)
		}
	}
	return ""
}

type serviceTestVersion struct{}

func (serviceTestVersion) Title() string                 { return "Bifroest test" }
func (serviceTestVersion) Version() string               { return "test" }
func (serviceTestVersion) Revision() string              { return "test" }
func (serviceTestVersion) Edition() sys.Edition          { return sys.EditionGeneric }
func (serviceTestVersion) BuildAt() time.Time            { return time.Time{} }
func (serviceTestVersion) Vendor() string                { return "Engity" }
func (serviceTestVersion) GoVersion() string             { return "test" }
func (serviceTestVersion) Os() sys.Os                    { return 0 }
func (serviceTestVersion) Arch() sys.Arch                { return 0 }
func (serviceTestVersion) Features() sys.VersionFeatures { return serviceTestVersionFeatures{} }

type serviceTestVersionFeatures struct{}

func (serviceTestVersionFeatures) ForEach(func(sys.VersionFeatureCategory)) {}
