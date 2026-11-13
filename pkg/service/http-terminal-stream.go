package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/gorilla/websocket"

	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/terminal"
)

const (
	webTerminalMessageLimit      = 16 << 10
	webTerminalInputQueue        = 4 // Four 16-KiB blocks, bounded by bytes rather than input message count.
	webTerminalControlQueue      = 16
	webTerminalMessagesPerSecond = 128
	webTerminalControlsPerSecond = 32
	webTerminalBytesPerSecond    = 64 << 10
)

type webTerminalTimings struct{ open, write, ping, pong time.Duration }
type webKeepAliveRequest struct{ interval, id string }

func defaultWebTerminalTimings() webTerminalTimings {
	return webTerminalTimings{open: 5 * time.Second, write: 5 * time.Second, ping: configuration.DefaultHttpKeepAlive, pong: 3 * configuration.DefaultHttpKeepAlive}
}

// This stream owns a single real WebSocket, not an SSH channel or saved terminal.
// One reader keeps processing control/heartbeat frames independently of task
// reads; full bounded queues fail closed rather than silently dropping input.
type webTerminalStream struct {
	socket                                      *websocket.Conn
	id                                          bconn.Id
	remote                                      webRemote
	ctx                                         context.Context
	cancel                                      context.CancelFunc
	timings                                     webTerminalTimings
	open                                        webTerminalOpen
	input                                       *webTerminalInputBuffer
	windows                                     chan terminal.Window
	signals                                     chan terminal.Signal
	workers                                     sync.WaitGroup
	closed                                      atomic.Bool
	writeMutex                                  sync.Mutex
	outputClosed                                bool
	finished                                    bool
	readMutex                                   sync.Mutex
	signalMutex                                 sync.Mutex
	signalStop, signalDone                      chan struct{}
	pingMutex                                   sync.Mutex
	awaitingPong                                string
	pingInterval, pongInterval                  time.Duration
	lastPong                                    time.Time
	heartbeatChanged                            chan struct{}
	configureKeepAlive                          func(string) (webKeepAlive, error)
	settingsReady                               chan struct{}
	settings                                    chan webKeepAliveRequest
	pongReceived                                chan struct{}
	budgetSince                                 time.Time
	budgetMessages, budgetControls, budgetBytes int
}

func newWebTerminalStream(ctx context.Context, socket *websocket.Conn, id bconn.Id, host bnet.Host, timings webTerminalTimings) *webTerminalStream {
	ctx, cancel := context.WithCancel(ctx)
	result := &webTerminalStream{socket: socket, id: id, remote: webRemote{host: host}, ctx: ctx, cancel: cancel, timings: timings, input: newWebTerminalInputBuffer(), windows: make(chan terminal.Window, webTerminalControlQueue), signals: make(chan terminal.Signal, webTerminalControlQueue), pingInterval: timings.ping, pongInterval: timings.pong, lastPong: time.Now(), heartbeatChanged: make(chan struct{}, 1), settingsReady: make(chan struct{}), settings: make(chan webKeepAliveRequest, webTerminalControlQueue), pongReceived: make(chan struct{})}
	socket.SetReadLimit(webTerminalMessageLimit)
	socket.SetPingHandler(func(value string) error {
		if err := result.accountInbound(len(value), true); err != nil {
			return err
		}
		return socket.WriteControl(websocket.PongMessage, []byte(value), time.Now().Add(timings.write))
	})
	socket.SetPongHandler(func(value string) error {
		if err := result.accountInbound(len(value), true); err != nil {
			return err
		}
		result.pingMutex.Lock()
		defer result.pingMutex.Unlock()
		matched := result.awaitingPong != "" && value == result.awaitingPong
		if matched {
			result.awaitingPong = ""
			result.lastPong = time.Now()
			close(result.pongReceived)
			result.pongReceived = make(chan struct{})
			return socket.SetReadDeadline(result.lastPong.Add(result.pongInterval))
		}
		return nil
	})
	return result
}

func (this *webTerminalStream) Id() bconn.Id              { return this.id }
func (this *webTerminalStream) Remote() bnet.Remote       { return this.remote }
func (*webTerminalStream) Logger() log.Logger             { return log.GetLogger("http.terminal") }
func (this *webTerminalStream) Lifetime() context.Context { return this.ctx }
func (this *webTerminalStream) Context() context.Context  { return this.ctx }
func (this *webTerminalStream) RawCommand() string        { return this.open.command }
func (this *webTerminalStream) Environ() []string {
	return append([]string(nil), this.open.environment...)
}
func (this *webTerminalStream) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	return terminal.ClonePty(this.open.pty), this.windows, this.open.hasPty
}

func (this *webTerminalStream) readOpen() (webTerminalOpen, error) {
	if err := this.socket.SetReadDeadline(time.Now().Add(this.timings.open)); err != nil {
		return webTerminalOpen{}, err
	}
	kind, data, err := this.socket.ReadMessage()
	if err != nil {
		return webTerminalOpen{}, err
	}
	if kind != websocket.TextMessage {
		return webTerminalOpen{}, fmt.Errorf("text open message required")
	}
	if err := this.accountInbound(len(data), true); err != nil {
		return webTerminalOpen{}, err
	}
	return parseWebTerminalOpen(data)
}

func (this *webTerminalStream) start() {
	this.workers.Add(3)
	go this.readLoop()
	go this.heartbeatLoop()
	go this.keepAliveSettingsLoop()
}
func (this *webTerminalStream) stop() { _ = this.Close(); this.Signals(nil); this.workers.Wait() }
func (this *webTerminalStream) Close() error {
	if !this.closed.CompareAndSwap(false, true) {
		return nil
	}
	this.cancel()
	return this.socket.Close()
}

func (this *webTerminalStream) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	this.readMutex.Lock()
	defer this.readMutex.Unlock()
	return this.input.read(this.ctx, data)
}
func (this *webTerminalStream) Write(data []byte) (int, error) { return this.writeOutput(0, data) }
func (this *webTerminalStream) Stderr() io.ReadWriter          { return webTerminalStderr{this} }
func (this *webTerminalStream) CloseWrite() error {
	this.writeMutex.Lock()
	defer this.writeMutex.Unlock()
	this.outputClosed = true
	return nil
}

func (this *webTerminalStream) writeOutput(channel byte, data []byte) (int, error) {
	this.writeMutex.Lock()
	defer this.writeMutex.Unlock()
	if this.outputClosed || this.finished {
		return 0, io.ErrClosedPipe
	}
	// The frame allocation is constant regardless of caller data length. The
	// socket write consumes the borrowed slice synchronously before reuse.
	var message [webTerminalMessageLimit]byte
	message[0] = channel
	written := 0
	for len(data) > 0 {
		if err := this.ctx.Err(); err != nil {
			return written, err
		}
		n := copy(message[1:], data)
		if err := this.socket.SetWriteDeadline(time.Now().Add(this.timings.write)); err != nil {
			_ = this.Close()
			return written, err
		}
		if err := this.socket.WriteMessage(websocket.BinaryMessage, message[:n+1]); err != nil {
			_ = this.Close()
			return written, err
		}
		written += n
		data = data[n:]
	}
	return written, nil
}
func (this *webTerminalStream) status(value any) error {
	this.writeMutex.Lock()
	defer this.writeMutex.Unlock()
	if this.finished {
		return io.ErrClosedPipe
	}
	if err := this.ctx.Err(); err != nil {
		return err
	}
	if err := this.socket.SetWriteDeadline(time.Now().Add(this.timings.write)); err != nil {
		return err
	}
	return this.socket.WriteJSON(value)
}
func (this *webTerminalStream) fail(code string) {
	_ = this.status(struct {
		Type string `json:"type"`
		Code string `json:"code"`
	}{"error", code})
}
func (this *webTerminalStream) finish(status uint32) {
	this.writeMutex.Lock()
	defer this.writeMutex.Unlock()
	if this.finished || this.ctx.Err() != nil {
		return
	}
	this.finished = true
	if err := this.socket.SetWriteDeadline(time.Now().Add(this.timings.write)); err != nil {
		return
	}
	if err := this.socket.WriteJSON(struct {
		Type   string `json:"type"`
		Status uint32 `json:"status"`
	}{"exit", status}); err == nil {
		_ = this.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "execution completed"), time.Now().Add(this.timings.write))
	}
}

type webTerminalStderr struct{ stream *webTerminalStream }

func (webTerminalStderr) Read([]byte) (int, error) { return 0, io.EOF }
func (this webTerminalStderr) Write(data []byte) (int, error) {
	return this.stream.writeOutput(1, data)
}

func (this *webTerminalStream) Signals(target chan<- terminal.Signal) {
	this.signalMutex.Lock()
	defer this.signalMutex.Unlock()
	if this.signalStop != nil {
		close(this.signalStop)
		<-this.signalDone
		this.signalStop = nil
	}
	if target == nil || this.ctx.Err() != nil {
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	this.signalStop, this.signalDone = stop, done
	go func() {
		defer close(done)
		for {
			select {
			case <-this.ctx.Done():
				return
			case <-stop:
				return
			case signal := <-this.signals:
				select {
				case target <- signal:
				case <-this.ctx.Done():
					return
				case <-stop:
					return
				}
			}
		}
	}()
}

func (this *webTerminalStream) accountInbound(size int, control bool) error {
	now := time.Now()
	if now.Sub(this.budgetSince) >= time.Second {
		this.budgetSince = now
		this.budgetMessages = 0
		this.budgetControls = 0
		this.budgetBytes = 0
	}
	this.budgetMessages++
	this.budgetBytes += size
	if control {
		this.budgetControls++
	}
	if this.budgetMessages > webTerminalMessagesPerSecond || this.budgetControls > webTerminalControlsPerSecond || this.budgetBytes > webTerminalBytesPerSecond {
		return fmt.Errorf("terminal inbound budget exceeded")
	}
	return nil
}

func (this *webTerminalStream) readLoop() {
	defer this.workers.Done()
	defer func() { _ = this.Close() }()
	defer close(this.windows)
	eof := false
	defer this.input.end()
	for {
		kind, data, err := this.socket.ReadMessage()
		if err != nil {
			return
		}
		if err := this.accountInbound(len(data), kind == websocket.TextMessage); err != nil {
			return
		}
		switch kind {
		case websocket.BinaryMessage:
			if eof || len(data) == 0 {
				return
			}
			if !this.input.append(data) {
				return
			}
		case websocket.TextMessage:
			if len(data) > 1024 {
				return
			}
			values, err := webTerminalObject(data, "type", "columns", "rows", "widthPixels", "heightPixels", "signal", "interval", "requestId")
			if err != nil {
				return
			}
			control, err := webTerminalString(values, "type", true)
			if err != nil {
				return
			}
			switch control {
			case "keepalive":
				if len(values) != 3 {
					return
				}
				interval, err := webTerminalString(values, "interval", true)
				if err != nil || len(interval) == 0 || len(interval) > 64 {
					return
				}
				requestID, err := webTerminalString(values, "requestId", true)
				if err != nil || len(requestID) > 16 {
					return
				}
				number, err := strconv.ParseUint(requestID, 10, 53)
				if err != nil || number == 0 || strconv.FormatUint(number, 10) != requestID {
					return
				}
				select {
				case this.settings <- webKeepAliveRequest{interval: interval, id: requestID}:
				case <-this.ctx.Done():
					return
				default:
					return
				}
			case "eof":
				if eof || len(values) != 1 {
					return
				}
				this.input.end()
				eof = true
			case "resize":
				if !this.open.hasPty {
					return
				}
				if _, exists := values["signal"]; exists {
					return
				}
				if _, exists := values["interval"]; exists {
					return
				}
				if _, exists := values["requestId"]; exists {
					return
				}
				window, err := parseWebTerminalWindow(values)
				if err != nil {
					return
				}
				select {
				case this.windows <- window:
				case <-this.ctx.Done():
					return
				default:
					return
				}
			case "signal":
				if len(values) != 2 {
					return
				}
				text, err := webTerminalString(values, "signal", true)
				if err != nil {
					return
				}
				signal, valid := normalizedTerminalSignal(terminal.Signal(text))
				if !valid {
					return
				}
				select {
				case this.signals <- signal:
				case <-this.ctx.Done():
					return
				default:
					return
				}
			default:
				return
			}
		default:
			return
		}
	}
}

func (this *webTerminalStream) heartbeatLoop() {
	defer this.workers.Done()
	defer func() { _ = this.Close() }()
	interval := func() time.Duration { this.pingMutex.Lock(); defer this.pingMutex.Unlock(); return this.pingInterval }
	timer := time.NewTimer(interval())
	defer timer.Stop()
	for {
		select {
		case <-this.ctx.Done():
			return
		case <-this.heartbeatChanged:
			timer.Reset(interval())
		case <-timer.C:
			timer.Reset(interval())
			if err := this.sendHeartbeat(); err != nil {
				return
			}
		}
	}
}

// Settings change transport cadence only. In particular, they never renew the
// session/activity lease, and cannot move the last proven pong into the future.
func (this *webTerminalStream) setKeepAliveInterval(ping, pong time.Duration) error {
	this.pingMutex.Lock()
	shorter := pong < this.pongInterval
	fresh := this.pongReceived
	this.pingMutex.Unlock()
	if shorter {
		// Keep the previous deadline intact until a real matching pong proves
		// the peer is alive. The dedicated settings worker leaves the reader
		// free to process that pong; no activity or liveness is fabricated.
		if err := this.sendHeartbeat(); err != nil {
			return err
		}
		select {
		case <-fresh:
		case <-this.ctx.Done():
			return this.ctx.Err()
		}
	}
	this.pingMutex.Lock()
	this.pingInterval, this.pongInterval = ping, pong
	err := this.socket.SetReadDeadline(this.lastPong.Add(pong))
	this.pingMutex.Unlock()
	if err != nil {
		return err
	}
	select {
	case this.heartbeatChanged <- struct{}{}:
	default:
	}
	return nil
}

func (this *webTerminalStream) sendHeartbeat() error {
	this.pingMutex.Lock()
	if this.awaitingPong != "" {
		this.pingMutex.Unlock()
		return nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		this.pingMutex.Unlock()
		return err
	}
	payload := hex.EncodeToString(nonce[:])
	this.awaitingPong = payload
	this.pingMutex.Unlock()
	return this.socket.WriteControl(websocket.PingMessage, []byte(payload), time.Now().Add(this.timings.write))
}

func (this *webTerminalStream) keepAliveSettingsLoop() {
	defer this.workers.Done()
	defer func() { _ = this.Close() }()
	select {
	case <-this.settingsReady:
	case <-this.ctx.Done():
		return
	}
	for {
		select {
		case <-this.ctx.Done():
			return
		case request := <-this.settings:
			this.pingMutex.Lock()
			configure := this.configureKeepAlive
			this.pingMutex.Unlock()
			if configure == nil {
				return
			}
			settings, err := configure(request.interval)
			if err != nil {
				return
			}
			if err := this.status(struct {
				Type      string       `json:"type"`
				RequestID string       `json:"requestId"`
				KeepAlive webKeepAlive `json:"keepAlive"`
			}{"keepalive", request.id, settings}); err != nil {
				return
			}
		}
	}
}
