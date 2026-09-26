package service

import (
	"fmt"
	"io"
	gonet "net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/echocat/slf4g/level"
	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
)

func TestExpectedSshHandshakeEndDoesNotHideAuthenticationErrors(t *testing.T) {
	require.True(t, isExpectedSshHandshakeEnd(&gossh.ServerAuthError{Errors: []error{gossh.ErrNoAuth}}))
	require.False(t, isExpectedSshHandshakeEnd(&gossh.ServerAuthError{Errors: []error{gossh.ErrNoAuth, fmt.Errorf("authentication backend unavailable")}}))
	require.False(t, isExpectedSshHandshakeEnd(fmt.Errorf("authentication backend unavailable")))
}

func TestClientDisconnectDuringAuthenticationIsLoggedAsDebug(t *testing.T) {
	provider := logrecording.NewProvider()
	provider.SetLevel(level.Debug)
	defer provider.HookGlobally()()

	tests := []struct {
		name       string
		authMethod func(gonet.Conn) gossh.AuthMethod
		reset      bool
	}{
		{
			name: "password",
			authMethod: func(conn gonet.Conn) gossh.AuthMethod {
				return gossh.PasswordCallback(func() (string, error) {
					_ = conn.Close()
					return "", io.EOF
				})
			},
		},
		{
			name:  "password-reset",
			reset: true,
			authMethod: func(conn gonet.Conn) gossh.AuthMethod {
				return gossh.PasswordCallback(func() (string, error) {
					if err := conn.(*gonet.TCPConn).SetLinger(0); err != nil {
						return "", err
					}
					_ = conn.Close()
					return "", io.EOF
				})
			},
		},
		{
			name: "keyboard-interactive",
			authMethod: func(conn gonet.Conn) gossh.AuthMethod {
				return gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
					_ = conn.Close()
					return nil, io.EOF
				})
			},
		},
		{
			name:  "keyboard-interactive-reset",
			reset: true,
			authMethod: func(conn gonet.Conn) gossh.AuthMethod {
				return gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
					if err := conn.(*gonet.TCPConn).SetLinger(0); err != nil {
						return nil, err
					}
					_ = conn.Close()
					return nil, io.EOF
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
			firstEvent := provider.Len()
			conn, err := gonet.DialTimeout("tcp", server.address, 5*time.Second)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })

			_, _, _, err = gossh.NewClientConn(conn, server.address, &gossh.ClientConfig{
				User:            server.username,
				Auth:            []gossh.AuthMethod{test.authMethod(conn)},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
				Timeout:         5 * time.Second,
			})
			require.Error(t, err)

			messageKey := provider.GetFieldKeysSpec().GetMessage()
			require.Eventually(t, func() bool {
				for _, event := range provider.GetAll()[firstEvent:] {
					if message, exists := event.Get(messageKey); exists && message == "SSH connection ended during handshake" {
						if test.reset && runtime.GOOS == "linux" {
							cause, _ := event.Get(provider.GetFieldKeysSpec().GetError())
							require.ErrorIs(t, cause.(error), syscall.ECONNRESET)
						}
						return event.GetLevel() == level.Debug
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond)
			for _, event := range provider.GetAll()[firstEvent:] {
				require.Less(t, event.GetLevel(), level.Error)
			}
		})
	}
}

func TestAuthenticationSystemFailureRemainsError(t *testing.T) {
	for _, test := range []struct {
		name  string
		cause error
	}{
		{"backend failure", fmt.Errorf("authentication backend unavailable")},
		{"backend unexpected EOF", fmt.Errorf("authentication backend: %w", io.ErrUnexpectedEOF)},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := logrecording.NewProvider()
			provider.SetLevel(level.Debug)
			defer provider.HookGlobally()()

			server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
			authorizer := &sdkMigrationAuthorizer{CloseableAuthorizer: server.service.authorizer}
			authorizer.authorizePassword = func(authorization.PasswordRequest) (authorization.Authorization, error) {
				return nil, test.cause
			}
			server.service.authorizer = authorizer
			firstEvent := provider.Len()

			client, err := dialSdkMigrationServer(server, gossh.Password("password"))
			if client != nil {
				_ = client.Close()
			}
			require.Error(t, err)

			messageKey := provider.GetFieldKeysSpec().GetMessage()
			require.Eventually(t, func() bool {
				for _, event := range provider.GetAll()[firstEvent:] {
					if message, exists := event.Get(messageKey); exists && message == "SSH operation failed" {
						return event.GetLevel() == level.Error
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond)
		})
	}
}
