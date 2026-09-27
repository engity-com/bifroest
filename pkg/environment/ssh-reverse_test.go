package environment

import (
	"context"
	"io"
	gonet "net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

type sshReverseRequest struct {
	Address string
	Port    uint32
}

type sshReverseCancelMode uint8

const (
	sshReverseCancelAccept sshReverseCancelMode = iota
	sshReverseCancelReject
	sshReverseCancelIgnore
)

func newReverseSshTarget(t *testing.T, blockFirst bool, cancelMode sshReverseCancelMode) (*sshTarget, <-chan sshReverseRequest) {
	t.Helper()
	target := newSshTarget(t)
	requested := make(chan sshReverseRequest, 4)
	var count atomic.Int32
	target.globalRequests = func(conn *gossh.ServerConn, requests <-chan *gossh.Request) {
		var listener gonet.Listener
		defer func() {
			if listener != nil {
				_ = listener.Close()
			}
		}()
		for request := range requests {
			switch request.Type {
			case "tcpip-forward":
				var bind sshReverseRequest
				if gossh.Unmarshal(request.Payload, &bind) != nil {
					_ = request.Reply(false, nil)
					continue
				}
				requested <- bind
				if blockFirst && count.Add(1) == 1 {
					// A canceled Listen must close the transport to unblock SendRequest.
					continue
				}
				var err error
				listener, err = gonet.Listen("tcp", gonet.JoinHostPort(bind.Address, strconv.Itoa(int(bind.Port))))
				if err != nil {
					_ = request.Reply(false, nil)
					continue
				}
				port := uint32(listener.Addr().(*gonet.TCPAddr).Port)
				if err := request.Reply(true, gossh.Marshal(&struct{ Port uint32 }{port})); err != nil {
					_ = listener.Close()
					return
				}
				go func(bind sshReverseRequest, listener gonet.Listener) {
					for {
						peer, err := listener.Accept()
						if err != nil {
							return
						}
						go func() {
							defer peer.Close()
							origin := peer.RemoteAddr().(*gonet.TCPAddr)
							forwarded := struct {
								Address    string
								Port       uint32
								Origin     string
								OriginPort uint32
							}{bind.Address, uint32(listener.Addr().(*gonet.TCPAddr).Port), origin.IP.String(), uint32(origin.Port)}
							channel, requests, err := conn.OpenChannel("forwarded-tcpip", gossh.Marshal(&forwarded))
							if err != nil {
								return
							}
							defer channel.Close()
							go gossh.DiscardRequests(requests)
							go func() { _, _ = io.Copy(channel, peer); _ = channel.CloseWrite() }()
							_, _ = io.Copy(peer, channel)
						}()
					}
				}(bind, listener)
			case "cancel-tcpip-forward":
				if cancelMode == sshReverseCancelIgnore {
					continue
				}
				if cancelMode == sshReverseCancelReject {
					_ = request.Reply(false, nil)
					continue
				}
				if listener != nil {
					_ = listener.Close()
					listener = nil
				}
				_ = request.Reply(true, nil)
			default:
				_ = request.Reply(false, nil)
			}
		}
	}
	return target, requested
}

func newReverseSshEnvironment(t *testing.T, target *sshTarget, forward, reverse bool) (*sshEnvironment, *SshRepository, context.CancelFunc) {
	t.Helper()
	lifetime, cancel := newSshTestContext()
	t.Cleanup(cancel)
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	conf.PortForwardingAllowed = template.BoolOf(forward)
	conf.ReversePortForwardingAllowed = template.BoolOf(reverse)
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repository.Close() })
	task := &sshTestTask{
		context: lifetime, connection: &sshTestConnection{id: connection.MustNewId(), context: lifetime},
		authorization: &sshTestAuthorization{session: &sshTestStoredSession{id: session.MustNewId()}},
		session:       newSshTestSession(lifetime, "", nil), taskType: TaskTypeShell,
	}
	resolved, err := repository.Ensure(task)
	require.NoError(t, err)
	return resolved.(*sshEnvironment), repository, cancel
}

func TestSshReverseForwardingPolicyAndNoLocalBind(t *testing.T) {
	target, requests := newReverseSshTarget(t, false, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	for _, test := range []struct{ forward, reverse bool }{{true, false}, {false, true}, {false, false}} {
		env, _, _ := newReverseSshEnvironment(t, target, test.forward, test.reverse)
		allowed, err := env.IsReversePortForwardingAllowed(bnet.MustNewHostPort("127.0.0.1:2222"))
		require.NoError(t, err)
		require.False(t, allowed)
		listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
		require.ErrorContains(t, err, "not allowed")
		require.Nil(t, listener)
	}
	require.Zero(t, target.connections.Load())
	require.Empty(t, requests)
}

func TestSshReverseForwardingResolvesPerRequest(t *testing.T) {
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString("target.example.org:22")
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	conf.ReversePortForwardingAllowed = template.MustNewBool(`{{ eq .targetUser "allowed" }}`)
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repository.Close() })
	ctx, cancel := newSshTestContext()
	t.Cleanup(cancel)
	base := &sshTestTask{context: ctx, targetUser: "denied"}
	denied, err := repository.resolveSettings(base)
	require.NoError(t, err)
	require.False(t, denied.reverseForwardAllowed)
	allowedRequest := *base
	allowedRequest.targetUser = "allowed"
	allowed, err := repository.resolveSettings(&allowedRequest)
	require.NoError(t, err)
	require.True(t, allowed.reverseForwardAllowed)
	require.True(t, allowed.forwardAllowed)
}

func TestSshReverseForwardingDataAndLifetime(t *testing.T) {
	target, requests := newReverseSshTarget(t, false, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	env, repository, cancelLifetime := newReverseSshEnvironment(t, target, true, true)
	allowed, err := env.IsReversePortForwardingAllowed(bnet.MustNewHostPort("127.0.0.1:2222"))
	require.NoError(t, err)
	require.True(t, allowed)
	listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	require.Equal(t, sshReverseRequest{"127.0.0.1", 0}, <-requests)
	addr := listener.Addr().(*gonet.TCPAddr)
	require.NotZero(t, addr.Port)
	require.Equal(t, "127.0.0.1", addr.IP.String())
	require.NoError(t, listener.Close()) // closed listener must not tear down the shared transport
	// Open another listener for the actual data path.
	listener, err = env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
	require.NoError(t, err)
	require.Equal(t, sshReverseRequest{"127.0.0.1", 0}, <-requests)
	peer, err := gonet.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	defer peer.Close()
	require.NoError(t, peer.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = peer.Write([]byte("ping"))
	require.NoError(t, err)
	accepted, err := listener.Accept()
	require.NoError(t, err)
	defer accepted.Close()
	buf := make([]byte, 4)
	_, err = io.ReadFull(accepted, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))
	_, err = accepted.Write([]byte("pong"))
	require.NoError(t, err)
	_, err = io.ReadFull(peer, buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf))
	require.Equal(t, int32(1), target.connections.Load())
	acceptDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		acceptDone <- err
	}()
	cancelLifetime()
	select {
	case err := <-acceptDone:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("connection cancellation did not close target listener")
	}
	require.Eventually(t, func() bool {
		repository.mutex.Lock()
		defer repository.mutex.Unlock()
		return len(repository.transports) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestSshReverseForwardingTransportLoss(t *testing.T) {
	target, _ := newReverseSshTarget(t, false, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	env, repository, _ := newReverseSshEnvironment(t, target, true, true)
	listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
	require.NoError(t, err)
	transport, err := repository.transportFor(env)
	require.NoError(t, err)
	acceptDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		acceptDone <- err
	}()
	require.NoError(t, transport.Close())
	select {
	case err := <-acceptDone:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("transport loss did not close target listener")
	}
}

func TestSshReverseForwardingCallbackCancellation(t *testing.T) {
	target, _ := newReverseSshTarget(t, false, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	env, repository, _ := newReverseSshEnvironment(t, target, true, true)
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := env.ListenReverseTCP(ctx, "127.0.0.1", 0)
	require.NoError(t, err)
	transport, err := repository.transportFor(env)
	require.NoError(t, err)
	acceptDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		acceptDone <- err
	}()
	cancel()
	select {
	case err := <-acceptDone:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("callback cancellation did not close target listener")
	}
	select {
	case <-transport.done:
		t.Fatal("canceling a live listener closed the shared transport")
	default:
	}
}

func TestSshReverseForwardingPendingListenCancellation(t *testing.T) {
	target, requests := newReverseSshTarget(t, true, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	env, repository, _ := newReverseSshEnvironment(t, target, true, true)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	finished := make(chan error, 1)
	go func() {
		listener, err := env.ListenReverseTCP(ctx, "127.0.0.1", 0)
		if listener != nil {
			_ = listener.Close()
		}
		finished <- err
	}()
	select {
	case bind := <-requests:
		require.Equal(t, sshReverseRequest{"127.0.0.1", 0}, bind)
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive tcpip-forward")
	}
	cancel()
	select {
	case err := <-finished:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("blocked SSH Listen was not interrupted")
	}
	listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	require.Equal(t, int32(2), target.connections.Load())
	require.Eventually(t, func() bool {
		repository.mutex.Lock()
		defer repository.mutex.Unlock()
		return len(repository.transports) == 1
	}, time.Second, 10*time.Millisecond)
}

func TestSshReverseForwardingTargetRejectsBind(t *testing.T) {
	target, requests := newReverseSshTarget(t, false, sshReverseCancelAccept)
	t.Cleanup(target.Close)
	env, _, _ := newReverseSshEnvironment(t, target, true, true)
	occupied, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()
	port := uint16(occupied.Addr().(*gonet.TCPAddr).Port)
	listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", port)
	require.Error(t, err)
	require.Nil(t, listener)
	select {
	case bind := <-requests:
		require.Equal(t, sshReverseRequest{"127.0.0.1", uint32(port)}, bind)
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive refused bind")
	}
}

func TestSshReverseForwardingCloseUnresponsiveTarget(t *testing.T) {
	for _, test := range []struct {
		name string
		mode sshReverseCancelMode
	}{
		{"ignores cancel", sshReverseCancelIgnore},
		{"rejects cancel", sshReverseCancelReject},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, _ := newReverseSshTarget(t, false, test.mode)
			t.Cleanup(target.Close)
			env, repository, _ := newReverseSshEnvironment(t, target, true, true)
			listener, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", 0)
			require.NoError(t, err)
			transport, err := repository.transportFor(env)
			require.NoError(t, err)
			address := listener.Addr().String()

			finished := make(chan error, 4)
			for range 4 {
				go func() { finished <- listener.Close() }()
			}
			var closeErr error
			select {
			case closeErr = <-finished:
				require.Error(t, closeErr)
			case <-time.After(3 * time.Second):
				t.Fatal("listener.Close blocked on cancel-tcpip-forward")
			}
			for range 3 {
				select {
				case err := <-finished:
					require.Equal(t, closeErr, err)
				case <-time.After(3 * time.Second):
					t.Fatal("concurrent listener.Close blocked")
				}
			}
			require.Equal(t, closeErr, listener.Close())
			select {
			case <-transport.done:
			default:
				t.Fatal("failed cancel did not close the shared target transport")
			}

			require.Eventually(t, func() bool {
				bound, err := gonet.Listen("tcp", address)
				if err != nil {
					return false
				}
				_ = bound.Close()
				return true
			}, time.Second, 10*time.Millisecond)
			port := uint16(listener.Addr().(*gonet.TCPAddr).Port)
			rebound, err := env.ListenReverseTCP(context.Background(), "127.0.0.1", port)
			require.NoError(t, err)
			require.Equal(t, address, rebound.Addr().String())
			require.Equal(t, int32(2), target.connections.Load())
			// The new target deliberately mishandles cancel as well.
			_ = rebound.Close()
		})
	}
}
