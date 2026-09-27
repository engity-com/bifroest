package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	gonet "net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

type reverseTCPSshEvent struct {
	kind        string
	address     string
	requestPort uint32
	port        uint32
}

type reverseTCPSshTarget struct {
	listener    gonet.Listener
	config      *gossh.ServerConfig
	hostKey     gossh.PublicKey
	events      chan reverseTCPSshEvent
	connections atomic.Int32
	wait        sync.WaitGroup
}

func newReverseTCPSshTarget(t *testing.T, identity gossh.PublicKey) *reverseTCPSshTarget {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	config := &gossh.ServerConfig{PublicKeyCallback: func(metadata gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		if metadata.User() != "target-user" || gossh.FingerprintSHA256(key) != gossh.FingerprintSHA256(identity) {
			return nil, fmt.Errorf("unexpected SSH target identity")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	target := &reverseTCPSshTarget{
		listener: listener, config: config, hostKey: signer.PublicKey(), events: make(chan reverseTCPSshEvent, 8),
	}
	target.wait.Add(1)
	go target.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		target.wait.Wait()
	})
	return target
}

func (target *reverseTCPSshTarget) serve() {
	defer target.wait.Done()
	for {
		raw, err := target.listener.Accept()
		if err != nil {
			return
		}
		target.wait.Add(1)
		go func() {
			defer target.wait.Done()
			conn, channels, requests, err := gossh.NewServerConn(raw, target.config)
			if err != nil {
				_ = raw.Close()
				return
			}
			defer conn.Close()
			target.connections.Add(1)
			go target.handleRequests(conn, requests)
			for channel := range channels {
				_ = channel.Reject(gossh.UnknownChannelType, "unsupported")
			}
		}()
	}
}

func (target *reverseTCPSshTarget) handleRequests(conn *gossh.ServerConn, requests <-chan *gossh.Request) {
	var listener gonet.Listener
	var address string
	var port uint32
	defer func() {
		if listener != nil {
			_ = listener.Close()
		}
	}()
	for request := range requests {
		var bind struct {
			Address string
			Port    uint32
		}
		if gossh.Unmarshal(request.Payload, &bind) != nil {
			_ = request.Reply(false, nil)
			continue
		}
		switch request.Type {
		case "tcpip-forward":
			if listener != nil || bind.Port > 65535 {
				_ = request.Reply(false, nil)
				continue
			}
			var err error
			listener, err = gonet.Listen("tcp", gonet.JoinHostPort(bind.Address, strconv.FormatUint(uint64(bind.Port), 10)))
			if err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			address, port = bind.Address, uint32(listener.Addr().(*gonet.TCPAddr).Port)
			if err := request.Reply(true, gossh.Marshal(&struct{ Port uint32 }{port})); err != nil {
				_ = listener.Close()
				listener = nil
				return
			}
			target.events <- reverseTCPSshEvent{"bind", address, bind.Port, port}
			go target.forward(conn, listener, address, port)
		case "cancel-tcpip-forward":
			if listener == nil || bind.Address != address || bind.Port != port {
				_ = request.Reply(false, nil)
				continue
			}
			_ = listener.Close()
			listener = nil
			_ = request.Reply(true, nil)
			target.events <- reverseTCPSshEvent{"cancel", bind.Address, bind.Port, port}
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func (target *reverseTCPSshTarget) forward(conn *gossh.ServerConn, listener gonet.Listener, address string, port uint32) {
	for {
		peer, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer peer.Close()
			origin := peer.RemoteAddr().(*gonet.TCPAddr)
			payload := struct {
				Address    string
				Port       uint32
				Origin     string
				OriginPort uint32
			}{address, port, origin.IP.String(), uint32(origin.Port)}
			channel, requests, err := conn.OpenChannel("forwarded-tcpip", gossh.Marshal(&payload))
			if err != nil {
				return
			}
			defer channel.Close()
			go gossh.DiscardRequests(requests)
			go func() {
				_, _ = io.Copy(channel, peer)
				_ = channel.CloseWrite()
			}()
			_, _ = io.Copy(peer, channel)
		}()
	}
}

func (target *reverseTCPSshTarget) nextEvent(t *testing.T) reverseTCPSshEvent {
	t.Helper()
	select {
	case event := <-target.events:
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("SSH target did not receive the forwarding request")
		return reverseTCPSshEvent{}
	}
}

func TestReverseTCPSshEnvironmentEndToEnd(t *testing.T) {
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(identity)
	require.NoError(t, err)
	directory := t.TempDir()
	identityPath := filepath.Join(directory, "target-identity")
	privateKey, err := gossh.MarshalPrivateKey(identity, "reverse TCP target identity")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(identityPath, pem.EncodeToMemory(privateKey), 0600))
	target := newReverseTCPSshTarget(t, signer.PublicKey())
	newProxy := func(t *testing.T, reverse bool) *authorizedKeysTestServer {
		t.Helper()
		return newAuthorizedKeysTestServerWithConfiguration(t, `permitlisten="127.0.0.1:*"`, nil, func(conf *configuration.Configuration) {
			sshEnvironment := &configuration.EnvironmentSsh{}
			require.NoError(t, sshEnvironment.SetDefaults())
			sshEnvironment.Address = template.MustNewString(target.listener.Addr().String())
			sshEnvironment.User = template.MustNewString("target-user")
			sshEnvironment.IdentityFiles = template.Strings{template.MustNewString(identityPath)}
			sshEnvironment.KnownHosts = crypto.KnownHosts(knownhosts.Line([]string{target.listener.Addr().String()}, target.hostKey))
			sshEnvironment.ReversePortForwardingAllowed = template.BoolOf(reverse)
			conf.Flows[0].Environment.V = sshEnvironment
		})
	}

	t.Run("denied", func(t *testing.T) {
		client := newProxy(t, false).mustDial(t)
		listener, err := client.Listen("tcp", "127.0.0.1:0")
		if listener != nil {
			_ = listener.Close()
		}
		require.Error(t, err)
		require.Zero(t, target.connections.Load(), "denied forwarding must not contact the target")
		require.Empty(t, target.events)
	})

	t.Run("allowed", func(t *testing.T) {
		client := newProxy(t, true).mustDial(t)
		listener, err := client.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })
		address := listener.Addr().(*gonet.TCPAddr)
		require.Equal(t, "127.0.0.1", address.IP.String())
		require.NotZero(t, address.Port)
		require.Equal(t, reverseTCPSshEvent{"bind", "127.0.0.1", 0, uint32(address.Port)}, target.nextEvent(t))
		require.EqualValues(t, 1, target.connections.Load())

		peer, err := gonet.DialTimeout("tcp", address.String(), time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = peer.Close() })
		require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
		_, err = peer.Write([]byte("ping"))
		require.NoError(t, err)
		forwarded, err := listener.Accept()
		require.NoError(t, err)
		t.Cleanup(func() { _ = forwarded.Close() })
		buffer := make([]byte, 4)
		_, err = io.ReadFull(forwarded, buffer)
		require.NoError(t, err)
		require.Equal(t, "ping", string(buffer))
		_, err = forwarded.Write([]byte("pong"))
		require.NoError(t, err)
		_, err = io.ReadFull(peer, buffer)
		require.NoError(t, err)
		require.Equal(t, "pong", string(buffer))
		require.NoError(t, peer.Close())
		require.NoError(t, forwarded.Close())

		require.NoError(t, listener.Close())
		require.Equal(t, reverseTCPSshEvent{"cancel", "127.0.0.1", uint32(address.Port), uint32(address.Port)}, target.nextEvent(t))
		rebound, err := gonet.Listen("tcp", address.String())
		require.NoError(t, err, "neither target nor Bifroest may retain the listener")
		require.NoError(t, rebound.Close())
	})
}
