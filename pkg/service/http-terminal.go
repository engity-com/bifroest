package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	bconn "github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

const (
	webTerminalMaximumSockets        = 64
	webTerminalMaximumSocketsPerPeer = 8
	webTerminalWireBytesPerSecond    = 96 << 10
)

func (this *webService) reserveTerminalSocket(peer netip.Addr) (func(), bool) {
	release, ok := this.operations.register()
	if !ok {
		return nil, false
	}
	this.mutex.Lock()
	if this.ctx.Err() != nil || this.sockets >= webTerminalMaximumSockets || this.socketPeers[peer] >= webTerminalMaximumSocketsPerPeer {
		this.mutex.Unlock()
		release()
		return nil, false
	}
	this.sockets++
	this.socketPeers[peer]++
	this.mutex.Unlock()
	return func() {
		this.mutex.Lock()
		this.sockets--
		this.socketPeers[peer]--
		if this.socketPeers[peer] == 0 {
			delete(this.socketPeers, peer)
		}
		this.mutex.Unlock()
		release()
	}, true
}

func (this *webService) serveWebSocketTerminal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		webError(w, http.StatusMethodNotAllowed, "GET upgrade required")
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || !websocket.IsWebSocketUpgrade(r) || len(websocket.Subprotocols(r)) != 1 || websocket.Subprotocols(r)[0] != webTerminalProtocol {
		webError(w, http.StatusBadRequest, "bifroest-terminal.v1 WebSocket upgrade required")
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		webError(w, http.StatusBadRequest, "upgrade body forbidden")
		return
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid direct peer")
		return
	}
	releaseHandshake, ok := this.admit(peer, false)
	if !ok {
		w.Header().Set("Retry-After", "60")
		webError(w, http.StatusTooManyRequests, "web request limit reached")
		return
	}
	releaseHandshake = sync.OnceFunc(releaseHandshake)
	defer releaseHandshake()
	releaseSocket, ok := this.reserveTerminalSocket(peer)
	if !ok {
		w.Header().Set("Retry-After", "1")
		webError(w, http.StatusTooManyRequests, "terminal connection limit reached")
		return
	}
	defer releaseSocket()
	id, err := bconn.NewId()
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "terminal unavailable")
		return
	}
	host, err := bnet.NewHost(peer.String())
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid direct peer")
		return
	}
	timings := this.terminalTimings
	upgrader := websocket.Upgrader{HandshakeTimeout: timings.open, ReadBufferSize: 4096, WriteBufferSize: 4096, EnableCompression: false, Subprotocols: []string{webTerminalProtocol},
		// The enclosing https.Boundary has already enforced the exact HTTPS
		// origin including effective port; absence still fails closed here.
		CheckOrigin: func(r *http.Request) bool { return len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") != "" },
	}
	socket, err := upgrader.Upgrade(webTerminalUpgradeWriter{ResponseWriter: w}, r, w.Header().Clone())
	if err != nil {
		return
	}
	stream := newWebTerminalStream(r.Context(), socket, id, host, timings)
	defer stream.stop()
	stopShutdown := context.AfterFunc(this.ctx, func() { _ = stream.Close() })
	defer stopShutdown()
	open, err := stream.readOpen()
	if err != nil {
		stream.fail("invalid-open")
		return
	}
	scope, err := requestWebScope(r, open.slug)
	if err != nil {
		stream.fail("invalid-open")
		return
	}
	access, err := this.lookup(scope, open.token, false)
	if err != nil {
		stream.fail("authentication-denied")
		return
	}
	if this.service.isManagementFlow(access.auth.Flow()) {
		stream.fail("terminal-unavailable")
		return
	}
	// Never retain the bearer proof in execution metadata, command, environment
	// or audit/recording. The verified grant remains server-side.
	token := open.token
	open.token = ""
	stream.open = open
	if err := socket.SetReadDeadline(time.Now().Add(timings.pong)); err != nil {
		return
	}
	stream.start()
	conn, err := this.connect(scope, token, stream)
	token = ""
	if err != nil {
		stream.fail("connection-denied")
		return
	}
	defer func() { _ = conn.Close(); <-conn.done }()
	releaseHandshake()
	if err := stream.status(struct {
		Type         string `json:"type"`
		ConnectionId string `json:"connectionId"`
	}{"ready", conn.Id().String()}); err != nil {
		return
	}
	status, err := this.service.executeTerminal(conn, stream, open.exec)
	if err != nil {
		stream.fail("execution-failed")
		return
	}
	stream.finish(uint32(status)) // The shared driver validated and audited it.
}

// In addition to decoded message budgets, charge actual WebSocket wire bytes.
// This bounds floods made of tiny/empty fragments before ReadMessage completes.
type webTerminalWireConn struct {
	net.Conn
	since time.Time
	bytes int
}

func (this *webTerminalWireConn) Close() error {
	// tls.Conn.Close can start a new close_notify write (with its own timeout)
	// after the WebSocket write deadline has already failed. A hijacked terminal
	// must unblock I/O immediately. Normal completion sends the WS close first.
	if conn, ok := this.Conn.(*tls.Conn); ok {
		return conn.NetConn().Close()
	}
	return this.Conn.Close()
}

func (this *webTerminalWireConn) Read(data []byte) (int, error) {
	n, err := this.Conn.Read(data)
	now := time.Now()
	if now.Sub(this.since) >= time.Second {
		this.since = now
		this.bytes = 0
	}
	this.bytes += n
	if this.bytes > webTerminalWireBytesPerSecond {
		return 0, fmt.Errorf("terminal wire budget exceeded")
	}
	return n, err
}

type webTerminalUpgradeWriter struct{ http.ResponseWriter }

func (this webTerminalUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := this.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("WebSocket hijack unavailable")
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	wrapped := &webTerminalWireConn{Conn: conn}
	// Gorilla rejects pre-handshake buffered data. Preserve that check instead
	// of discarding bytes or allowing an unmetered reader into an active socket.
	if rw.Reader.Buffered() > 0 {
		return wrapped, rw, nil
	}
	return wrapped, bufio.NewReadWriter(bufio.NewReaderSize(wrapped, 4096), bufio.NewWriterSize(wrapped, 4096)), nil
}
