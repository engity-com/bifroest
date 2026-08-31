package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	gonet "net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	glssh "github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/engity-com/bifroest/pkg/authorization"
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
			require.NoError(t, agent.RequestAgentForwarding(sshSession))
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

type authorizedKeysTestServer struct {
	address  string
	username string
	signer   gossh.Signer
}

func newAuthorizedKeysTestServer(t *testing.T, options string, testEnvironment *authorizedKeysTestEnvironment) *authorizedKeysTestServer {
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

	svc, err := (&Service{Configuration: conf, Version: serviceTestVersion{}}).prepare()
	require.NoError(t, err)
	require.NoError(t, svc.environments.Close())
	svc.environments = &authorizedKeysTestRepository{environment: testEnvironment}

	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- svc.server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = svc.server.Close()
		_ = listener.Close()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			t.Error("SSH server did not stop")
		}
		require.NoError(t, svc.Close())
	})

	return &authorizedKeysTestServer{listener.Addr().String(), username, signer}
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
	t.Cleanup(func() { require.NoError(t, client.Close()) })
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
