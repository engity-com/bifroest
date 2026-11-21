package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/gorilla/websocket"
)

const (
	sshTunnelWriteTimeout              = 30 * time.Second
	sshTunnelMaximumConnections        = 1024
	sshTunnelMaximumConnectionsPerPeer = 64
)

// One listener, hence one SSH admission/handshake/channel-limit scope, serves
// every HTTP transport. It can never dial arbitrary addresses or parse PROXY.
type sshTunnel struct {
	incoming   chan net.Conn
	done       chan struct{}
	closeOnce  sync.Once
	ready      atomic.Bool
	operations *connectionLifecycle
	mutex      sync.Mutex
	peers      map[string]int
	active     int
	logger     log.Logger
	monitoring *serviceMonitoring
}

func (this *sshTunnel) transportError(operation string, err error) {
	if this.logger == nil || err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
		return
	}
	logger := this.logger.With("operation", operation)
	if closeErr, ok := errors.AsType[*websocket.CloseError](err); ok {
		// Never log a peer-supplied close reason or stream payload.
		logger.With("closeStatus", closeErr.Code).Debug("SSH tunnel WebSocket closed")
	} else {
		logger.WithError(err).Debug("SSH tunnel transport ended")
	}
}

func newSshTunnel() *sshTunnel {
	return &sshTunnel{incoming: make(chan net.Conn), done: make(chan struct{}), operations: newConnectionLifecycle(), peers: make(map[string]int)}
}

func (this *sshTunnel) Accept() (net.Conn, error) {
	select {
	case <-this.done:
		return nil, net.ErrClosed
	case conn := <-this.incoming:
		return conn, nil
	}
}
func (this *sshTunnel) Addr() net.Addr { return tunnelAddr("internal SSH tunnel") }
func (this *sshTunnel) Close() error {
	this.closeOnce.Do(func() { this.ready.Store(false); this.operations.stop(); close(this.done) })
	return nil
}

type tunnelAddr string

func (this tunnelAddr) Network() string { return "https" }
func (this tunnelAddr) String() string  { return string(this) }

type tunnelConn struct {
	net.Conn
	local, remote net.Addr
}

func (this *tunnelConn) LocalAddr() net.Addr  { return this.local }
func (this *tunnelConn) RemoteAddr() net.Addr { return this.remote }

func (this *sshTunnel) admit(peer string) (func(), bool) {
	release, ok := this.operations.register()
	if !ok {
		return nil, false
	}
	this.mutex.Lock()
	// Separate bounded transport slots, never occupy WebUI API workers. The
	// SSH server additionally enforces MaxStartups and global MaxConnections.
	if this.active >= sshTunnelMaximumConnections || this.peers[peer] >= sshTunnelMaximumConnectionsPerPeer {
		this.monitoring.reject("ssh_tunnel", "connections")
		this.mutex.Unlock()
		release()
		return nil, false
	}
	this.active++
	this.peers[peer]++
	this.mutex.Unlock()
	return func() {
		this.mutex.Lock()
		this.active--
		this.peers[peer]--
		if this.peers[peer] == 0 {
			delete(this.peers, peer)
		}
		this.mutex.Unlock()
		release()
	}, true
}

func (this *sshTunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !this.ready.Load() {
		http.Error(w, "SSH tunnel is not ready", http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "invalid SSH tunnel request", http.StatusBadRequest)
		return
	}
	ws := websocket.IsWebSocketUpgrade(r)
	if r.ProtoMajor == 1 && r.ProtoMinor < 1 || (r.Method != http.MethodPost && (!ws || r.Method != http.MethodGet)) {
		w.Header().Set("Allow", "POST, GET")
		http.Error(w, "streaming POST or WebSocket GET required", http.StatusMethodNotAllowed)
		return
	}
	if !ws && (r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("Upgrade") != "") || ws && (r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(websocket.Subprotocols(r)) != 0) {
		http.Error(w, "binary SSH stream required", http.StatusBadRequest)
		return
	}
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid direct peer", http.StatusBadRequest)
		return
	}
	release, ok := this.admit(remote.IP.String())
	if !ok {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "SSH tunnel limit reached", http.StatusTooManyRequests)
		return
	}
	defer release()
	server, bridge := net.Pipe()
	defer bridge.Close()
	defer server.Close()
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		local = this.Addr()
	}
	conn := &tunnelConn{Conn: server, local: local, remote: remote}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	select {
	case this.incoming <- conn:
	case <-this.done:
		http.Error(w, "SSH tunnel is stopping", http.StatusServiceUnavailable)
		return
	case <-ctx.Done():
		http.Error(w, "SSH tunnel is busy", http.StatusServiceUnavailable)
		return
	}
	if ws {
		this.serveWebSocket(w, r, bridge)
		return
	}
	this.serveStream(w, r, bridge)
}

func (this *sshTunnel) serveStream(w http.ResponseWriter, r *http.Request, bridge net.Conn) {
	controller := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if err := controller.EnableFullDuplex(); err != nil {
			http.Error(w, "duplex unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if err := controller.SetReadDeadline(time.Time{}); err != nil {
		http.Error(w, "stream unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	_ = controller.SetWriteDeadline(time.Now().Add(sshTunnelWriteTimeout))
	w.WriteHeader(http.StatusOK)
	if controller.Flush() != nil {
		return
	}
	finish := this.monitoring.channelOpened(r, "ssh_tunnel")
	var end atomic.Uint32
	defer func() { finish(monitoringCloseReason(end.Load())) }()
	stopped := make(chan struct{})
	stop := context.AfterFunc(r.Context(), func() {
		defer close(stopped)
		_ = bridge.Close()
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	})
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		_, _ = io.Copy(bridge, r.Body)
		_ = bridge.Close()
	}()
	defer func() {
		// A read deadline used solely to finish cleanup can cancel net/http's
		// request context. Disarm cancellation before it could expire the write
		// deadline and suppress the response's final chunk.
		if !stop() {
			<-stopped
		}
		_ = bridge.Close()
		// Interrupt before Close: net/http's Body.Close can wait for a blocked
		// read. Do not expire the write deadline on normal SSH completion.
		_ = controller.SetReadDeadline(time.Now())
		_ = r.Body.Close()
		<-inputDone
	}()
	copyErr := copyTunnelOutput(bridge, func(data []byte) error {
		_ = controller.SetWriteDeadline(time.Now().Add(sshTunnelWriteTimeout))
		if _, err := w.Write(data); err != nil {
			return err
		}
		return controller.Flush()
	})
	if !errors.Is(copyErr, io.EOF) {
		end.Store(monitoringEndReason(copyErr))
	}
}

func (this *sshTunnel) serveWebSocket(w http.ResponseWriter, r *http.Request, bridge net.Conn) {
	// The outer HTTPS boundary already validated supplied origins, TLS and Host.
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, HandshakeTimeout: 5 * time.Second, ReadBufferSize: 32 << 10, WriteBufferSize: 32 << 10, EnableCompression: false}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	finish := this.monitoring.channelOpened(r, "ssh_tunnel")
	var end atomic.Uint32
	defer func() { finish(monitoringCloseReason(end.Load())) }()
	_ = ws.UnderlyingConn().SetDeadline(time.Time{})
	// Message boundaries have no SSH meaning. NextReader streams through fixed
	// buffers with net.Pipe backpressure; never allocate/read a whole message.
	ws.SetReadLimit(0)
	// curl writes close payload bytes to stdout. A clean byte stream requires
	// an empty close frame, including when replying to a peer's close.
	ws.SetCloseHandler(func(int, string) error {
		return ws.WriteControl(websocket.CloseMessage, nil, time.Now().Add(sshTunnelWriteTimeout))
	})
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		defer bridge.Close()
		for {
			kind, reader, err := ws.NextReader()
			if err != nil {
				reason := monitoringEndReason(err)
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) && (closeErr.Code == websocket.CloseNormalClosure || closeErr.Code == websocket.CloseGoingAway) {
					reason = 2
				}
				end.CompareAndSwap(0, reason)
				this.transportError("read", err)
				return
			}
			if kind != websocket.BinaryMessage {
				end.CompareAndSwap(0, 4)
				if this.logger != nil {
					this.logger.With("messageType", kind).Debug("non-binary SSH tunnel message rejected")
				}
				return
			}
			if _, err := io.Copy(bridge, reader); err != nil {
				this.transportError("read-message", err)
				return
			}
		}
	}()
	defer func() { _ = bridge.Close(); _ = ws.Close(); <-inputDone }()
	copyErr := copyTunnelOutput(bridge, func(data []byte) error {
		_ = ws.SetWriteDeadline(time.Now().Add(sshTunnelWriteTimeout))
		return ws.WriteMessage(websocket.BinaryMessage, data)
	})
	if !errors.Is(copyErr, io.EOF) {
		end.CompareAndSwap(0, monitoringEndReason(copyErr))
	}
	this.transportError("write", copyErr)
	_ = ws.WriteControl(websocket.CloseMessage, nil, time.Now().Add(sshTunnelWriteTimeout))
}

func copyTunnelOutput(reader io.Reader, write func([]byte) error) error {
	buffer := make([]byte, 32<<10)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if writeErr := write(buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}
