package protocol

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/xtaci/smux"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestReverseTCPHost(t *testing.T) {
	for _, host := range []string{"", "localhost", "127.0.0.1", "::1", "fe80::1%lo"} {
		require.NoError(t, validateReverseTCPHost(host), "host %q", host)
	}
	for _, host := range []string{"bad:host", "[::1]", "local\x00host", "::1\x00"} {
		require.Error(t, validateReverseTCPHost(host), "host %q", host)
	}
}

type reverseTCPTestRef struct {
	sessionId session.Id
	conn      net.Conn
}

func (r reverseTCPTestRef) SessionId() session.Id       { return r.sessionId }
func (r reverseTCPTestRef) PublicKey() crypto.PublicKey { return nil }
func (r reverseTCPTestRef) Dial(context.Context) (net.Conn, error) {
	return r.conn, nil
}

func TestReverseTCPCancelBeforeResponse(t *testing.T) {
	key, err := (crypto.KeyRequirement{Type: crypto.KeyTypeEd25519}).GenerateKey(nil)
	require.NoError(t, err)
	master, err := NewMaster(context.Background(), key)
	require.NoError(t, err)
	sessionId, err := session.NewId()
	require.NoError(t, err)
	serverConfig, err := (&Imp{MasterPublicKey: key.PublicKey(), SessionId: sessionId}).createTlsConfig()
	require.NoError(t, err)

	for _, cancelContext := range []string{"request", "session"} {
		t.Run(cancelContext, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ready := make(chan struct{})
			serverDone := make(chan error, 1)
			go func() {
				tlsConn := tls.Server(server, serverConfig)
				conn := codec.NewMsgPackConn(tlsConn)
				defer conn.Close()
				if err := tlsConn.Handshake(); err != nil {
					serverDone <- err
					return
				}
				var header Header
				if err := header.DecodeMsgPack(conn); err != nil {
					serverDone <- err
					return
				}
				var req reverseTCPRequest
				if err := req.DecodeMsgPack(conn); err != nil {
					serverDone <- err
					return
				}
				close(ready)
				var buf [1]byte
				_, err := conn.Read(buf[:])
				serverDone <- err
			}()

			ctx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			sessionCtx, cancelSession := context.WithCancel(context.Background())
			defer cancelSession()
			result := make(chan error, 1)
			go func() {
				_, err := master.methodListenReverseTCP(ctx, sessionCtx, reverseTCPTestRef{sessionId, client}, connection.Id{}, "127.0.0.1", 0)
				result <- err
			}()
			select {
			case <-ready:
			case err := <-serverDone:
				t.Fatalf("fake IMP failed before request: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("fake IMP did not receive request")
			}
			if cancelContext == "request" {
				cancelRequest()
			} else {
				cancelSession()
			}
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not release response decode")
			}
			select {
			case err := <-serverDone:
				require.True(t, errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed), "fake IMP read: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("connection did not close on cancellation")
			}
		})
	}
}

func TestReverseTCPAddressFrame(t *testing.T) {
	var wire bytes.Buffer
	remote := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}
	local := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5678}
	require.NoError(t, writeReverseTCPAddresses(&wire, remote, local))
	_, err := wire.Write([]byte{0, 1, 255})
	require.NoError(t, err)
	gotRemote, gotLocal, err := readReverseTCPAddresses(&wire)
	require.NoError(t, err)
	require.Equal(t, remote.String(), gotRemote.String())
	require.Equal(t, local.String(), gotLocal.String())
	remaining, err := io.ReadAll(&wire)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 1, 255}, remaining)
}

func TestReverseTCPAddressFrameRejectsInvalidAddresses(t *testing.T) {
	for _, addresses := range [][2]string{
		{"host:1234", "127.0.0.1:5678"},
		{"127.0.0.1:0", "127.0.0.1:5678"},
		{"127.0.0.1:1234", "127.0.0.1:0"},
	} {
		var wire bytes.Buffer
		payload, err := msgpack.Marshal(addresses)
		require.NoError(t, err)
		require.Less(t, len(payload), 256)
		_, err = wire.Write([]byte{0, byte(len(payload))})
		require.NoError(t, err)
		_, err = wire.Write(payload)
		require.NoError(t, err)
		_, _, err = readReverseTCPAddresses(&wire)
		require.Error(t, err)
	}
	_, _, err := readReverseTCPAddresses(bytes.NewReader([]byte{2, 1}))
	require.Error(t, err)
}

func TestReverseTCPDataFrames(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client, err := smux.Client(left, baseNamedPipeConfig())
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, baseNamedPipeConfig())
	require.NoError(t, err)
	defer server.Close()
	stream, err := client.OpenStream()
	require.NoError(t, err)
	defer stream.Close()
	peer, err := server.AcceptStream()
	require.NoError(t, err)
	defer peer.Close()

	masterConn := &reverseTCPConn{stream: stream}
	impConn := &reverseTCPConn{stream: peer}
	request := strings.Repeat("request", 5000)
	response := strings.Repeat("response", 5000)
	_, err = masterConn.Write([]byte(request))
	require.NoError(t, err)
	require.NoError(t, masterConn.CloseWrite())
	require.NoError(t, masterConn.CloseWrite())
	_, err = masterConn.Write([]byte("late"))
	require.ErrorIs(t, err, io.ErrClosedPipe)
	got, err := io.ReadAll(impConn)
	require.NoError(t, err)
	require.Equal(t, request, string(got))
	_, err = impConn.Write([]byte(response))
	require.NoError(t, err)
	require.NoError(t, impConn.CloseWrite())
	got, err = io.ReadAll(masterConn)
	require.NoError(t, err)
	require.Equal(t, response, string(got))
}

func TestReverseTCPDataFrameRejectsOversize(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client, err := smux.Client(left, baseNamedPipeConfig())
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, baseNamedPipeConfig())
	require.NoError(t, err)
	defer server.Close()
	stream, err := client.OpenStream()
	require.NoError(t, err)
	defer stream.Close()
	peer, err := server.AcceptStream()
	require.NoError(t, err)
	defer peer.Close()

	var header [2]byte
	binary.BigEndian.PutUint16(header[:], reverseTCPChunkSize+1)
	_, err = stream.Write(header[:])
	require.NoError(t, err)
	_, err = (&reverseTCPConn{stream: peer}).Read(make([]byte, 1))
	require.ErrorContains(t, err, "invalid reverse TCP data frame length")
}

func TestReverseTCPDataFrameRejectsTruncatedPayload(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client, err := smux.Client(left, baseNamedPipeConfig())
	require.NoError(t, err)
	defer client.Close()
	server, err := smux.Server(right, baseNamedPipeConfig())
	require.NoError(t, err)
	defer server.Close()
	stream, err := client.OpenStream()
	require.NoError(t, err)
	peer, err := server.AcceptStream()
	require.NoError(t, err)
	defer peer.Close()

	_, err = stream.Write([]byte{0, 4, 'x'})
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	got, err := io.ReadAll(&reverseTCPConn{stream: peer})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "x", string(got))
}
