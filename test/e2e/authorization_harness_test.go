//go:build e2e && linux && amd64

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func startAuthorizationService(f *fixture, authorizationYAML string) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reserve SSH listen port: %w", err)
	}
	f.port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		return err
	}

	if err := os.MkdirAll(f.sessionStorage, 0700); err != nil {
		return err
	}
	configurationPath := filepath.Join(f.tempDir, "authorization.yaml")
	configuration := fmt.Sprintf(authorizationConfiguration,
		yamlString(net.JoinHostPort(f.host, f.port)),
		yamlString(f.hostKey),
		yamlString(f.sessionStorage),
		authorizationYAML,
	)
	if err := os.WriteFile(configurationPath, []byte(configuration), 0600); err != nil {
		return fmt.Errorf("write authorization configuration: %w", err)
	}

	f.bifroestProc, err = launchProcess(f.repoRoot, nil, f.bifroest,
		"run", "--configuration="+configurationPath, "--log.level=DEBUG")
	if err != nil {
		return fmt.Errorf("start Bifroest: %w", err)
	}
	if err := pollProcess(20*time.Second, f.bifroestProc, func() error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(f.host, f.port), 500*time.Millisecond)
		if err != nil {
			return err
		}
		return conn.Close()
	}); err != nil {
		return fmt.Errorf("wait for Bifroest: %w", err)
	}
	return nil
}

func dialAuthorizationSSH(f *fixture, user string, auth gossh.AuthMethod, timeout time.Duration) (*gossh.Client, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		client, err := dialAuthorizationSSHOnce(f, user, auth, timeout)
		if err == nil || !isTransientSSHDialError(err) {
			return client, err
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, lastErr
}

func dialAuthorizationSSHOnce(f *fixture, user string, auth gossh.AuthMethod, timeout time.Duration) (*gossh.Client, error) {
	hostKey, _, _, _, err := gossh.ParseAuthorizedKey(mustRead(f.hostKey + ".pub"))
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(f.host, f.port)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sshConn, channels, requests, err := gossh.NewClientConn(conn, address, &gossh.ClientConfig{
		User:            user,
		Auth:            []gossh.AuthMethod{auth},
		HostKeyCallback: gossh.FixedHostKey(hostKey),
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return gossh.NewClient(sshConn, channels, requests), nil
}

func runAuthorizationSession(client *gossh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Run("true")
}

const authorizationConfiguration = `startMessage: '{{""}}'
ssh:
  addresses:
    - %s
  keys:
    hostKeys:
      - %s
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
  idleTimeout: 20s
  maxTimeout: 1m
  gracefulShutdownTimeout: 3s
  handshakeTimeout: 15s
  sessionRequestTimeout: 10s
session:
  type: fs
  storage: %s
  idleTimeout: 30s
  maxTimeout: 1m
  maxConnections: 8
flows:
  - name: authorization-e2e
    authorization:
%s
    environment:
      type: dummy
      exitCode: 0
      banner: '{{""}}'
`
