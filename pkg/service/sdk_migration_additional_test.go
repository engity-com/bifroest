package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	gonet "net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	berrors "github.com/engity-com/bifroest/pkg/errors"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	btemplate "github.com/engity-com/bifroest/pkg/template"
)

func TestCopyForwardedConnectionStopsOnlyWhenChannelCloses(t *testing.T) {
	sshPeer, sshSide := gonet.Pipe()
	destinationSide, destinationPeer := gonet.Pipe()
	t.Cleanup(func() {
		_ = sshPeer.Close()
		_ = sshSide.Close()
		_ = destinationSide.Close()
		_ = destinationPeer.Close()
	})
	requests := make(chan *gossh.Request)
	done := make(chan error, 1)
	go func() {
		done <- copyForwardedConnection(context.Background(), requests, sshSide, destinationSide, nil)
	}()

	select {
	case err := <-done:
		t.Fatalf("idle forwarding stopped before the SSH channel closed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(requests)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("forwarding did not stop after the SSH channel closed")
	}
}

func TestSdkMigrationPasswordAuthenticationDistinguishesRejectionFromSystemError(t *testing.T) {
	testSdkMigrationAuthenticationFailure(t, gossh.Password("rejected-password"), func(authorizer *sdkMigrationAuthorizer, err error) {
		authorizer.authorizePassword = func(req authorization.PasswordRequest) (authorization.Authorization, error) {
			if err != nil {
				return nil, err
			}
			return authorization.Forbidden(req.Connection().Remote()), nil
		}
	})
}

func TestSdkMigrationKeyboardInteractiveAuthenticationDistinguishesRejectionFromSystemError(t *testing.T) {
	testSdkMigrationAuthenticationFailure(t, gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
		return []string{"rejected-password"}, nil
	}), func(authorizer *sdkMigrationAuthorizer, err error) {
		authorizer.authorizeInteractive = func(req authorization.InteractiveRequest) (authorization.Authorization, error) {
			if err != nil {
				return nil, err
			}
			return authorization.Forbidden(req.Connection().Remote()), nil
		}
	})
}

func testSdkMigrationAuthenticationFailure(t *testing.T, firstMethod gossh.AuthMethod, configure func(*sdkMigrationAuthorizer, error)) {
	t.Helper()
	tests := []struct {
		name              string
		callbackError     error
		wantPublicKeyAuth bool
	}{
		{name: "ordinary-rejection", wantPublicKeyAuth: true},
		{name: "user-error", callbackError: berrors.Newf(berrors.User, "credentials rejected"), wantPublicKeyAuth: true},
		{name: "system-error", callbackError: fmt.Errorf("authentication backend unavailable")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
			authorizer := &sdkMigrationAuthorizer{CloseableAuthorizer: server.service.authorizer}
			configure(authorizer, test.callbackError)
			server.service.authorizer = authorizer

			client, err := dialSdkMigrationServer(server, firstMethod, gossh.PublicKeys(server.signer))
			if client != nil {
				t.Cleanup(func() { _ = client.Close() })
			}
			if test.wantPublicKeyAuth {
				require.NoError(t, err)
				require.Positive(t, authorizer.publicKeyCalls.Load(), "the rejected method must allow public-key fallback")
				sshSession, sessionErr := client.NewSession()
				require.NoError(t, sessionErr)
				require.NoError(t, sshSession.Run("fallback"))
			} else {
				require.Error(t, err)
				require.Zero(t, authorizer.publicKeyCalls.Load(), "a system error must abort before public-key fallback")
			}
		})
	}
}

func TestSdkMigrationBannerRenderErrorAbortsHandshake(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing-banner")
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.Banner = btemplate.MustNewString(fmt.Sprintf("{{%q | file}}", missingFile))
	})
	authorizer := &sdkMigrationAuthorizer{CloseableAuthorizer: server.service.authorizer}
	server.service.authorizer = authorizer

	client, err := server.dial()
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)
	require.Zero(t, authorizer.publicKeyCalls.Load(), "banner rendering must fail before authentication")
}

func TestSdkMigrationConfiguredSshAlgorithmsAreNegotiatedAndRejected(t *testing.T) {
	tests := []struct {
		name                    string
		configureServer         func(*configuration.Configuration)
		configureAllowedClient  func(*gossh.ClientConfig)
		configureRejectedClient func(*gossh.ClientConfig)
	}{
		{
			name: "cipher",
			configureServer: func(conf *configuration.Configuration) {
				conf.Ssh.Messages.Ciphers = bssh.Ciphers{bssh.CipherAes256Ctr}
			},
			configureAllowedClient: func(conf *gossh.ClientConfig) {
				conf.Ciphers = []string{bssh.CipherAes256Ctr.String()}
			},
			configureRejectedClient: func(conf *gossh.ClientConfig) {
				conf.Ciphers = []string{bssh.CipherAes128Ctr.String()}
			},
		},
		{
			name: "key-exchange",
			configureServer: func(conf *configuration.Configuration) {
				conf.Ssh.Keys.Exchanges = bssh.KeyExchanges{bssh.KeyExchangeCurve25519Sha256}
			},
			configureAllowedClient: func(conf *gossh.ClientConfig) {
				conf.KeyExchanges = []string{bssh.KeyExchangeCurve25519Sha256.String()}
			},
			configureRejectedClient: func(conf *gossh.ClientConfig) {
				conf.KeyExchanges = []string{bssh.KeyExchangeEcdh256.String()}
			},
		},
		{
			name: "mac",
			configureServer: func(conf *configuration.Configuration) {
				conf.Ssh.Messages.Ciphers = bssh.Ciphers{bssh.CipherAes256Ctr}
				conf.Ssh.Messages.Authentications = bssh.MessageAuthentications{bssh.MessageAuthenticationHmacSha2B256}
			},
			configureAllowedClient: func(conf *gossh.ClientConfig) {
				conf.Ciphers = []string{bssh.CipherAes256Ctr.String()}
				conf.MACs = []string{bssh.MessageAuthenticationHmacSha2B256.String()}
			},
			configureRejectedClient: func(conf *gossh.ClientConfig) {
				conf.Ciphers = []string{bssh.CipherAes256Ctr.String()}
				conf.MACs = []string{bssh.MessageAuthenticationHmacSha2B512.String()}
			},
		},
		{
			name: "host-key",
			configureAllowedClient: func(conf *gossh.ClientConfig) {
				conf.HostKeyAlgorithms = []string{gossh.KeyAlgoED25519}
			},
			configureRejectedClient: func(conf *gossh.ClientConfig) {
				conf.HostKeyAlgorithms = []string{gossh.KeyAlgoECDSA256}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, test.configureServer)

			client, err := dialSdkMigrationServerWithClientConfig(server, test.configureAllowedClient)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			rejectedClient, err := dialSdkMigrationServerWithClientConfig(server, test.configureRejectedClient)
			if rejectedClient != nil {
				_ = rejectedClient.Close()
			}
			require.Error(t, err)
			var negotiationError *gossh.AlgorithmNegotiationError
			require.ErrorAs(t, err, &negotiationError)
		})
	}
}

func TestSdkMigrationBannerAndRememberMeAreWrittenToClient(t *testing.T) {
	const password = "remember-me-password"
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	rememberMeSigner, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)

	testEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
		_, err := io.WriteString(task.SshSession(), "environment-output")
		return 0, err
	}}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", testEnvironment, func(conf *configuration.Configuration) {
		conf.Ssh.Banner = btemplate.MustNewString("sdk-migration-banner")
		conf.Ssh.Keys.RememberMeNotification = btemplate.MustNewString("sdk-migration-remember-me\n")
		simpleAuthorization := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		require.NoError(t, simpleAuthorization.Entries[0].Password.Set("plain:"+password))
	})

	var banner string
	client, err := dialSdkMigrationServerWithClientConfig(server, func(conf *gossh.ClientConfig) {
		conf.Auth = []gossh.AuthMethod{gossh.PublicKeys(rememberMeSigner), gossh.Password(password)}
		conf.BannerCallback = func(message string) error {
			banner = message
			return nil
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.Equal(t, "sdk-migration-banner", banner)

	sshSession, err := client.NewSession()
	require.NoError(t, err)
	output, err := sshSession.Output("show-messages")
	require.NoError(t, err)
	require.Equal(t, "sdk-migration-remember-me\nenvironment-output", string(output))
}

func TestSdkMigrationGlobalMaxConnectionsReleasesSlot(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxConnections = 1
	})
	first := server.mustDial(t)
	require.EqualValues(t, 1, server.service.activeConnections.Load())

	second, err := server.dial()
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)
	require.EqualValues(t, 1, server.service.activeConnections.Load())

	require.NoError(t, first.Close())
	require.Eventually(t, func() bool {
		return server.service.activeConnections.Load() == 0
	}, 2*time.Second, 10*time.Millisecond)
	replacement := server.mustDial(t)
	require.EqualValues(t, 1, server.service.activeConnections.Load())
	require.NoError(t, replacement.Close())
}

func TestSdkMigrationSessionMaxConnectionsReleasesSlot(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, func(conf *configuration.Configuration) {
		conf.Ssh.MaxConnections = 10
		conf.Session.V.(*configuration.SessionFs).MaxConnections = 1
	})
	first := server.mustDial(t)

	second, err := server.dial()
	if second != nil {
		_ = second.Close()
	}
	require.Error(t, err)

	require.NoError(t, first.Close())
	var replacement *gossh.Client
	require.Eventually(t, func() bool {
		candidate, dialErr := server.dial()
		if dialErr != nil {
			return false
		}
		replacement = candidate
		return true
	}, 2*time.Second, 10*time.Millisecond, "the session connection slot was not released")
	t.Cleanup(func() { _ = replacement.Close() })
	sshSession, err := replacement.NewSession()
	require.NoError(t, err)
	require.NoError(t, sshSession.Run("replacement"))
}

func TestSdkMigrationProxyProtocolV1AndV2ExposeSourceAddress(t *testing.T) {
	const sourceAddress = "198.51.100.23"
	tests := []struct {
		name   string
		header []byte
	}{
		{name: "v1", header: []byte("PROXY TCP4 " + sourceAddress + " 127.0.0.1 42300 22\r\n")},
		{name: "v2", header: sdkMigrationProxyV2Header(sourceAddress, "127.0.0.1", 42300, 22)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testEnvironment := &authorizedKeysTestEnvironment{run: func(task environment.Task) (int, error) {
				_, err := io.WriteString(task.SshSession(), task.Authorization().Remote().Host().String())
				return 0, err
			}}
			server := newAuthorizedKeysTestServerWithConfiguration(t, `from="`+sourceAddress+`"`, testEnvironment, func(conf *configuration.Configuration) {
				conf.Ssh.ProxyProtocol = true
			})

			clientWithoutHeader, err := server.dial()
			if clientWithoutHeader != nil {
				_ = clientWithoutHeader.Close()
			}
			require.Error(t, err, "a PROXY-enabled listener must require a PROXY header")

			client, err := dialSdkMigrationProxyServer(server, test.header)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })
			sshSession, err := client.NewSession()
			require.NoError(t, err)
			output, err := sshSession.Output("remote-address")
			require.NoError(t, err)
			require.Equal(t, sourceAddress, string(output))
		})
	}
}

type sdkMigrationAuthorizer struct {
	authorization.CloseableAuthorizer
	authorizePassword    func(authorization.PasswordRequest) (authorization.Authorization, error)
	authorizeInteractive func(authorization.InteractiveRequest) (authorization.Authorization, error)
	publicKeyCalls       atomic.Int32
}

func (this *sdkMigrationAuthorizer) AuthorizePublicKey(req authorization.PublicKeyRequest) (authorization.Authorization, error) {
	this.publicKeyCalls.Add(1)
	return this.CloseableAuthorizer.AuthorizePublicKey(req)
}

func (this *sdkMigrationAuthorizer) AuthorizePassword(req authorization.PasswordRequest) (authorization.Authorization, error) {
	if this.authorizePassword != nil {
		return this.authorizePassword(req)
	}
	return this.CloseableAuthorizer.AuthorizePassword(req)
}

func (this *sdkMigrationAuthorizer) AuthorizeInteractive(req authorization.InteractiveRequest) (authorization.Authorization, error) {
	if this.authorizeInteractive != nil {
		return this.authorizeInteractive(req)
	}
	return this.CloseableAuthorizer.AuthorizeInteractive(req)
}

func dialSdkMigrationServer(server *authorizedKeysTestServer, methods ...gossh.AuthMethod) (*gossh.Client, error) {
	return dialSdkMigrationServerWithClientConfig(server, func(conf *gossh.ClientConfig) {
		conf.Auth = methods
	})
}

func dialSdkMigrationServerWithClientConfig(server *authorizedKeysTestServer, configure func(*gossh.ClientConfig)) (*gossh.Client, error) {
	conf := &gossh.ClientConfig{
		User:            server.username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
		Timeout:         5 * time.Second,
	}
	if configure != nil {
		configure(conf)
	}
	return gossh.Dial("tcp", server.address, conf)
}

func dialSdkMigrationProxyServer(server *authorizedKeysTestServer, header []byte) (*gossh.Client, error) {
	conn, err := gonet.DialTimeout("tcp", server.address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	closeConn := true
	defer func() {
		if closeConn {
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := io.Copy(conn, bytes.NewReader(header)); err != nil {
		return nil, err
	}
	sshConn, channels, requests, err := gossh.NewClientConn(conn, server.address, &gossh.ClientConfig{
		User:            server.username,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(server.signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
	})
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = sshConn.Close()
		return nil, err
	}
	closeConn = false
	return gossh.NewClient(sshConn, channels, requests), nil
}

func sdkMigrationProxyV2Header(source, destination string, sourcePort, destinationPort uint16) []byte {
	header := make([]byte, 28)
	copy(header, []byte("\r\n\r\n\x00\r\nQUIT\n"))
	header[12] = 0x21 // Version 2, PROXY command.
	header[13] = 0x11 // TCP over IPv4.
	binary.BigEndian.PutUint16(header[14:16], 12)
	copy(header[16:20], gonet.ParseIP(source).To4())
	copy(header[20:24], gonet.ParseIP(destination).To4())
	binary.BigEndian.PutUint16(header[24:26], sourcePort)
	binary.BigEndian.PutUint16(header[26:28], destinationPort)
	return header
}

var _ authorization.CloseableAuthorizer = (*sdkMigrationAuthorizer)(nil)
