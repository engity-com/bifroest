package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	bconn "github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

const webManagementProtocol = "bifroest-management.v1"

type webManagementContextKey struct{}
type webManagementRequestIDContextKey struct{}
type webManagementChannel struct {
	stream   *webTerminalStream
	conn     *terminalConnection
	access   *webAccess
	scope    webScope
	request  *http.Request
	jobs     chan webManagementJob
	mutex    sync.Mutex
	pending  map[string]context.CancelFunc
	last     uint64
	progress bool
}
type webManagementJob struct {
	id, action string
	fields     map[string]string
	ctx        context.Context
	cancel     context.CancelFunc
}

// Only an in-process request dispatched by this live channel can borrow its
// admission. No HTTP header, cookie, selector or second bearer can select it.
func (this *webService) managementAccess(r *http.Request, scope webScope) (*webAccess, error) {
	channel, ok := r.Context().Value(webManagementContextKey{}).(*webManagementChannel)
	if !ok {
		return this.lookup(scope, webBearer(r), false)
	}
	if channel.scope != scope || channel.conn.IsClosed() || channel.conn.check(false) != nil {
		return nil, errWebAccessDenied
	}
	base := &environmentContext{service: this.service, connection: channel.conn, authorization: channel.access.auth, executionContext: r.Context()}
	if err := this.validate(base, channel.access); err != nil {
		return nil, err
	}
	channel.access.mutex.Lock()
	closed := channel.access.closed
	channel.access.mutex.Unlock()
	if closed {
		return nil, errWebAccessDenied
	}
	return channel.access, nil
}

func (this *webService) serveWebSocketManagement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		webError(w, 405, "GET upgrade required")
		return
	}
	protocols := websocket.Subprotocols(r)
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || !websocket.IsWebSocketUpgrade(r) || len(protocols) != 1 || protocols[0] != webManagementProtocol || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		webError(w, 400, "bifroest-management.v1 WebSocket upgrade required")
		return
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, 400, "invalid direct peer")
		return
	}
	release, ok := this.admit(peer, false)
	if !ok {
		webError(w, 429, "web request limit reached")
		return
	}
	release = sync.OnceFunc(release)
	defer release()
	releaseSocket, ok := this.reserveTerminalSocket(peer)
	if !ok {
		webError(w, 429, "connection limit reached")
		return
	}
	defer releaseSocket()
	id, err := bconn.NewId()
	if err != nil {
		webError(w, 503, "management unavailable")
		return
	}
	host, err := bnet.NewHost(peer.String())
	if err != nil {
		webError(w, 400, "invalid direct peer")
		return
	}
	timings := this.terminalTimings
	upgrader := websocket.Upgrader{HandshakeTimeout: timings.open, ReadBufferSize: 4096, WriteBufferSize: 4096, EnableCompression: false, Subprotocols: []string{webManagementProtocol}, CheckOrigin: func(r *http.Request) bool { return len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") != "" }}
	socket, err := upgrader.Upgrade(webTerminalUpgradeWriter{ResponseWriter: w}, r, w.Header().Clone())
	if err != nil {
		return
	}
	stream := newWebTerminalStream(r.Context(), socket, id, host, timings)
	defer stream.stop()
	stop := context.AfterFunc(this.ctx, func() { _ = stream.Close() })
	defer stop()
	if socket.SetReadDeadline(time.Now().Add(timings.open)) != nil {
		return
	}
	kind, data, err := socket.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		return
	}
	values, err := webTerminalObject(data, "type", "accessToken", "slug", "keepAlive", "progress")
	if err != nil || len(values) < 3 {
		return
	}
	var token, slug, interval, command string
	for name, target := range map[string]*string{"type": &command, "accessToken": &token, "slug": &slug, "keepAlive": &interval} {
		value, present := values[name]
		if !present && name == "keepAlive" {
			continue
		}
		if json.Unmarshal(value, target) != nil {
			return
		}
	}
	if command != "open" || len(interval) > 64 {
		return
	}
	progress := false
	if raw, present := values["progress"]; present {
		var version string
		if json.Unmarshal(raw, &version) != nil || version != "counts-v1" {
			return
		}
		progress = true
	}
	scope, err := requestWebScope(r, slug)
	if err != nil {
		return
	}
	access, err := this.lookup(scope, token, false)
	if err != nil || !this.service.isManagementFlow(access.auth.Flow()) {
		stream.fail("authentication-denied")
		return
	}
	conn, err := this.connect(scope, token, stream)
	token = ""
	clear(values)
	clear(data)
	if err != nil {
		stream.fail("connection-denied")
		return
	}
	defer func() { _ = conn.Close(); <-conn.done }()
	channel := &webManagementChannel{stream: stream, conn: conn, access: access, scope: scope, request: r, jobs: make(chan webManagementJob, 4), pending: make(map[string]context.CancelFunc), progress: progress}
	defer func() {
		this.mutex.Lock()
		for key, value := range this.confirmations {
			if value.channel == channel {
				delete(this.confirmations, key)
			}
		}
		this.mutex.Unlock()
	}()
	base := &environmentContext{service: this.service, connection: conn, authorization: access.auth, executionContext: conn.Lifetime()}
	stream.configureKeepAlive = func(value string) (webKeepAlive, error) {
		if conn.check(false) != nil {
			return webKeepAlive{}, errWebAccessDenied
		}
		if this.validate(base, access) != nil {
			return webKeepAlive{}, errWebAccessDenied
		}
		return this.configureKeepAlive(base, stream, value)
	}
	// The independent reader must process real pongs while a shorter cadence is
	// being negotiated. Reuse the terminal heartbeat/settings implementation.
	if socket.SetReadDeadline(time.Now().Add(timings.pong)) != nil {
		return
	}
	stream.workers.Add(3)
	go channel.readLoop()
	go stream.heartbeatLoop()
	go stream.keepAliveSettingsLoop()
	policy, err := this.configureKeepAlive(base, stream, interval)
	if err != nil {
		return
	}
	if stream.status(struct {
		Type         string       `json:"type"`
		ConnectionID string       `json:"connectionId"`
		KeepAlive    webKeepAlive `json:"keepAlive"`
	}{"ready", id.String(), policy}) != nil {
		return
	}
	close(stream.settingsReady)
	release()
	for {
		select {
		case <-conn.Lifetime().Done():
			return
		case job := <-channel.jobs:
			channel.serve(this, job)
			channel.mutex.Lock()
			delete(channel.pending, job.id)
			channel.mutex.Unlock()
			job.cancel()
		}
	}
}

func managementChannelAction(action string) bool {
	switch action {
	case "management/flows/list", "management/version/show", "management/sessions/list", "management/sessions/show", "management/auditlogs/list", "management/recordings/list", "management/sessions/prepare", "management/sessions/confirm", "management/sessions/cancel", "management/artifacts/recording", "management/artifacts/audit":
		return true
	}
	return false
}

func (this *webManagementChannel) readLoop() {
	defer this.stream.workers.Done()
	defer func() { _ = this.stream.Close() }()
	for {
		kind, data, err := this.stream.socket.ReadMessage()
		if err != nil || kind != websocket.TextMessage || this.stream.accountInbound(len(data), true) != nil {
			return
		}
		values, err := webTerminalObject(data, "type", "requestId", "action", "fields", "interval")
		if err != nil {
			return
		}
		command, err := webTerminalString(values, "type", true)
		if err != nil {
			return
		}
		id, err := webTerminalString(values, "requestId", true)
		if err != nil {
			return
		}
		number, err := strconv.ParseUint(id, 10, 53)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != id {
			return
		}
		switch command {
		case "keepalive":
			interval, err := webTerminalString(values, "interval", true)
			if err != nil || len(values) != 3 || len(interval) == 0 || len(interval) > 64 {
				return
			}
			select {
			case this.stream.settings <- webKeepAliveRequest{interval: interval, id: id}:
			case <-this.stream.ctx.Done():
				return
			default:
				return
			}
		case "cancel":
			if len(values) != 2 || number > this.last {
				return
			}
			this.mutex.Lock()
			cancel := this.pending[id]
			this.mutex.Unlock()
			if cancel != nil {
				cancel()
			}
		case "request":
			if len(values) != 4 || number <= this.last {
				return
			}
			this.last = number
			action, err := webTerminalString(values, "action", true)
			if err != nil || !managementChannelAction(action) {
				return
			}
			fields := map[string]string{}
			if json.Unmarshal(values["fields"], &fields) != nil || fields == nil || len(fields) > 16 {
				return
			}
			if _, ok := fields["slug"]; ok {
				return
			}
			ctx, cancel := context.WithCancel(this.conn.Lifetime())
			this.mutex.Lock()
			full := len(this.pending) >= 4
			if !full {
				this.pending[id] = cancel
			}
			this.mutex.Unlock()
			if full {
				cancel()
				return
			}
			select {
			case this.jobs <- webManagementJob{id: id, action: action, fields: fields, ctx: ctx, cancel: cancel}:
			case <-ctx.Done():
				cancel()
				return
			default:
				cancel()
				return
			}
		default:
			return
		}
	}
}

func (this *webManagementChannel) serve(service *webService, job webManagementJob) {
	job.fields["slug"] = this.scope.Slug
	data, err := json.Marshal(job.fields)
	if err != nil {
		return
	}
	ctx := context.WithValue(job.ctx, webManagementContextKey{}, this)
	ctx = context.WithValue(ctx, webManagementRequestIDContextKey{}, job.id)
	request := this.request.Clone(ctx)
	request.Method = http.MethodPost
	request.URL.Path = webAPI + job.action
	request.URL.RawPath = ""
	request.Header = request.Header.Clone()
	request.Header.Del("Authorization")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Del("Content-Encoding")
	request.TransferEncoding = nil
	request.Body = io.NopCloser(bytes.NewReader(data))
	request.ContentLength = int64(len(data))
	output := &webManagementResponse{channel: this, id: job.id, ctx: ctx, header: make(http.Header), cancel: job.cancel}
	service.ServeHTTP(output, request)
	if !output.started {
		output.WriteHeader(200)
	}
	if ctx.Err() == nil && this.conn.check(false) == nil {
		_ = this.stream.status(struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
		}{"complete", job.id})
	} else if this.stream.ctx.Err() == nil {
		_ = this.stream.status(struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
		}{"canceled", job.id})
	}
}

// The existing handlers still own strict completion, budgets, per-operation
// audit/recording and authorization. This adapter only frames their output.
type webManagementResponse struct {
	channel       *webManagementChannel
	id            string
	ctx           context.Context
	header        http.Header
	started       bool
	cancel        context.CancelFunc
	writing       atomic.Bool
	progressAt    time.Time
	progressPhase string
}

func (this *webManagementResponse) ManagementProgress(progress managementReadProgress) error {
	if !this.channel.progress {
		return nil
	}
	if err := this.ctx.Err(); err != nil {
		return err
	}
	if this.channel.conn.check(false) != nil {
		return errWebAccessDenied
	}
	// Once data begins, the adapter's bounded byte frames provide transfer
	// progress. Never interleave a new pre-response status into body framing.
	if this.started {
		return nil
	}
	now := time.Now()
	if progress.Phase == this.progressPhase && now.Sub(this.progressAt) < 100*time.Millisecond && (progress.Total < 0 || progress.Completed != progress.Total) {
		return nil
	}
	this.progressAt, this.progressPhase = now, progress.Phase
	return this.channel.stream.status(struct {
		Type      string `json:"type"`
		RequestID string `json:"requestId"`
		managementReadProgress
	}{"progress", this.id, progress})
}

func (this *webManagementResponse) Header() http.Header { return this.header }
func (this *webManagementResponse) WriteHeader(status int) {
	if this.started {
		return
	}
	this.started = true
	media := this.header.Get("Content-Type")
	if strings.ContainsAny(media, "\r\n") {
		this.cancel()
		return
	}
	if this.channel.stream.status(struct {
		Type        string `json:"type"`
		RequestID   string `json:"requestId"`
		Status      int    `json:"status"`
		ContentType string `json:"contentType"`
	}{"response", this.id, status, media}) != nil {
		this.cancel()
	}
}
func (this *webManagementResponse) Write(data []byte) (int, error) {
	if !this.started {
		this.WriteHeader(200)
	}
	stream := this.channel.stream
	stream.writeMutex.Lock()
	defer stream.writeMutex.Unlock()
	var frame [webTerminalMessageLimit]byte
	id, _ := strconv.ParseUint(this.id, 10, 53)
	binary.BigEndian.PutUint64(frame[:8], id)
	written := 0
	for len(data) > 0 {
		this.writing.Store(true)
		if err := this.ctx.Err(); err != nil {
			this.writing.Store(false)
			return written, err
		}
		n := copy(frame[8:], data)
		if err := stream.socket.SetWriteDeadline(time.Now().Add(stream.timings.write)); err != nil {
			this.writing.Store(false)
			return written, err
		}
		if err := stream.socket.WriteMessage(websocket.BinaryMessage, frame[:n+8]); err != nil {
			this.writing.Store(false)
			_ = stream.Close()
			return written, err
		}
		this.writing.Store(false)
		written += n
		data = data[n:]
	}
	return written, nil
}
func (this *webManagementResponse) FlushError() error          { return this.ctx.Err() }
func (*webManagementResponse) SetReadDeadline(time.Time) error { return nil }
func (this *webManagementResponse) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		this.cancel()
		if this.writing.Load() {
			return this.channel.stream.Close()
		}
	}
	return nil
}

var _ http.ResponseWriter = (*webManagementResponse)(nil)
