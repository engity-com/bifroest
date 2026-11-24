package nanoserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type nativeSSHKeepAlive struct {
	client        *ssh.Client
	stopRequested chan struct{}
	done          chan struct{}
	stopOnce      sync.Once
	detachCancel  func() bool
	result        error // Read only after done closes.
}

func startNativeSSHKeepAlive(ctx context.Context, client *ssh.Client, interval time.Duration) *nativeSSHKeepAlive {
	current := &nativeSSHKeepAlive{client: client, stopRequested: make(chan struct{}), done: make(chan struct{})}
	// SendRequest has no context parameter. The existing fixture context closes
	// the transport if a peer stops replying; no additional timeout is introduced.
	current.detachCancel = context.AfterFunc(ctx, func() { _ = client.Close() })
	go func() {
		defer close(current.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-current.stopRequested:
				return
			case <-ctx.Done():
				current.result = ctx.Err()
				return
			case <-ticker.C:
				select {
				case <-current.stopRequested:
					return
				default:
				}
				accepted, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					if ctx.Err() != nil {
						current.result = ctx.Err()
					} else {
						current.result = fmt.Errorf("SSH keepalive request: %w", err)
					}
					return
				}
				// Bifroest explicitly accepts this request, as covered by its
				// existing real SSH tunnel keepalive test.
				if !accepted {
					current.result = fmt.Errorf("SSH keepalive request was rejected")
					return
				}
			}
		}
	}()
	return current
}

func (this *nativeSSHKeepAlive) failure() error {
	select {
	case <-this.done:
		return this.result
	default:
		return nil
	}
}

func (this *nativeSSHKeepAlive) stop() error {
	// Preserve the transport for the explicit SSH exit; an in-flight reply is
	// bounded by the original fixture context. Fatal cleanup uses abort instead.
	this.stopOnce.Do(func() { close(this.stopRequested) })
	<-this.done
	this.detachCancel()
	return this.result
}

func (this *nativeSSHKeepAlive) abort() {
	// Fatal-test cleanup must unblock an unanswered SendRequest before joining.
	_ = this.client.Close()
	_ = this.stop()
}

func newNativeSSHKeepAliveTestPair(t *testing.T) (*ssh.Client, *ssh.ServerConn, <-chan *ssh.Request) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	type handshake struct {
		server   *ssh.ServerConn
		requests <-chan *ssh.Request
		err      error
	}
	ready := make(chan handshake, 1)
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			ready <- handshake{err: err}
			return
		}
		defer raw.Close()
		closeOnCancel := context.AfterFunc(t.Context(), func() { _ = raw.Close() })
		defer closeOnCancel()
		server, channels, requests, err := ssh.NewServerConn(raw, serverConfig)
		ready <- handshake{server, requests, err}
		if err != nil {
			return
		}
		defer server.Close()
		for channel := range channels {
			_ = channel.Reject(ssh.Prohibited, "no execution channels in the keepalive test")
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(5*time.Second)))
	connection, channels, requests, err := ssh.NewClientConn(raw, listener.Addr().String(), &ssh.ClientConfig{User: "keepalive-test", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	require.NoError(t, err)
	require.NoError(t, raw.SetDeadline(time.Time{}))
	client := ssh.NewClient(connection, channels, requests)
	t.Cleanup(func() { _ = client.Close() })
	peer := <-ready
	require.NoError(t, peer.err)
	return client, peer.server, peer.requests
}

func receiveNativeSSHKeepAliveRequest(t *testing.T, requests <-chan *ssh.Request) *ssh.Request {
	t.Helper()
	select {
	case request := <-requests:
		require.NotNil(t, request)
		require.Equal(t, "keepalive@openssh.com", request.Type)
		require.True(t, request.WantReply)
		require.Empty(t, request.Payload)
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("missing SSH keepalive request")
		return nil
	}
}

func TestNativeSSHKeepAliveAcknowledgedStopJoinsAndPreservesTransport(t *testing.T) {
	client, _, requests := newNativeSSHKeepAliveTestPair(t)
	keepAlive := startNativeSSHKeepAlive(t.Context(), client, time.Millisecond)
	t.Cleanup(keepAlive.abort)
	request := receiveNativeSSHKeepAliveRequest(t, requests)
	stopped := make(chan error, 1)
	go func() { stopped <- keepAlive.stop() }()
	<-keepAlive.stopRequested
	require.NoError(t, request.Reply(true, nil))
	for {
		select {
		case err := <-stopped:
			require.NoError(t, err)
			require.NoError(t, keepAlive.stop(), "stop is idempotent")
			// A request on this same transport must still work, with no ticker
			// request arriving after stop has joined the keepalive goroutine.
			replied := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("after-stop", true, nil)
				replied <- err
			}()
			select {
			case request := <-requests:
				require.NotNil(t, request)
				require.Equal(t, "after-stop", request.Type)
				require.NoError(t, request.Reply(true, nil))
			case <-time.After(5 * time.Second):
				t.Fatal("normal stop closed the existing SSH transport")
			}
			require.NoError(t, <-replied)
			return
		case request := <-requests:
			require.NotNil(t, request)
			require.Equal(t, "keepalive@openssh.com", request.Type)
			require.NoError(t, request.Reply(true, nil))
		case <-time.After(5 * time.Second):
			t.Fatal("keepalive did not join after its reply")
		}
	}
}

func TestNativeSSHKeepAliveReportsReplyAndTransportFailures(t *testing.T) {
	for _, mode := range []string{"rejected", "transport-closed"} {
		t.Run(mode, func(t *testing.T) {
			client, server, requests := newNativeSSHKeepAliveTestPair(t)
			keepAlive := startNativeSSHKeepAlive(t.Context(), client, time.Millisecond)
			t.Cleanup(keepAlive.abort)
			request := receiveNativeSSHKeepAliveRequest(t, requests)
			if mode == "rejected" {
				require.NoError(t, request.Reply(false, nil))
			} else {
				require.NoError(t, server.Close())
			}
			select {
			case <-keepAlive.done:
			case <-time.After(5 * time.Second):
				t.Fatal("keepalive did not surface its request failure")
			}
			require.Error(t, keepAlive.failure())
			require.Error(t, keepAlive.stop())
			if mode == "rejected" {
				require.ErrorContains(t, keepAlive.failure(), "rejected")
			}
		})
	}
}

func TestNativeSSHKeepAliveAbortAndContextCancellationUnblockPendingReply(t *testing.T) {
	for _, mode := range []string{"fatal-cleanup", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			client, _, requests := newNativeSSHKeepAliveTestPair(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			keepAlive := startNativeSSHKeepAlive(ctx, client, time.Millisecond)
			t.Cleanup(keepAlive.abort)
			receiveNativeSSHKeepAliveRequest(t, requests) // Deliberately never reply.
			stopped := make(chan struct{})
			go func() {
				if mode == "fatal-cleanup" {
					keepAlive.abort()
				} else {
					cancel()
					_ = keepAlive.stop()
				}
				close(stopped)
			}()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup leaked a goroutine waiting for a keepalive reply")
			}
			require.Error(t, keepAlive.failure())
			if mode == "parent-cancel" {
				require.ErrorIs(t, keepAlive.failure(), context.Canceled)
			}
		})
	}
}
