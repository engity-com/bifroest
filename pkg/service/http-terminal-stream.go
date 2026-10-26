package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/gorilla/websocket"

	bconn "github.com/engity-com/bifroest/pkg/connection"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/terminal"
)

const (
	webTerminalMessageLimit      = 16 << 10
	webTerminalInputQueue        = 4 // At most 64 KiB of queued stdin, plus the current read.
	webTerminalControlQueue      = 16
	webTerminalMessagesPerSecond = 128
	webTerminalControlsPerSecond = 32
	webTerminalBytesPerSecond    = 64 << 10
)

type webTerminalTimings struct{ open, write, ping, pong time.Duration }

func defaultWebTerminalTimings() webTerminalTimings {
	return webTerminalTimings{open: 5 * time.Second, write: 5 * time.Second, ping: 15 * time.Second, pong: 45 * time.Second}
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
	input                                       chan []byte
	windows                                     chan terminal.Window
	signals                                     chan terminal.Signal
	workers                                     sync.WaitGroup
	closed                                      atomic.Bool
	writeMutex                                  sync.Mutex
	outputClosed                                bool
	readMutex                                   sync.Mutex
	pending                                     []byte
	signalMutex                                 sync.Mutex
	signalStop, signalDone                      chan struct{}
	pingMutex                                   sync.Mutex
	awaitingPong                                string
	budgetSince                                 time.Time
	budgetMessages, budgetControls, budgetBytes int
}

func newWebTerminalStream(ctx context.Context, socket *websocket.Conn, id bconn.Id, host bnet.Host, timings webTerminalTimings) *webTerminalStream {
	ctx, cancel := context.WithCancel(ctx)
	result := &webTerminalStream{socket: socket, id: id, remote: webRemote{host: host}, ctx: ctx, cancel: cancel, timings: timings, input: make(chan []byte, webTerminalInputQueue), windows: make(chan terminal.Window, webTerminalControlQueue), signals: make(chan terminal.Signal, webTerminalControlQueue)}
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
		matched := result.awaitingPong != "" && value == result.awaitingPong
		if matched {
			result.awaitingPong = ""
		}
		result.pingMutex.Unlock()
		if matched {
			return socket.SetReadDeadline(time.Now().Add(timings.pong))
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
	this.workers.Add(2)
	go this.readLoop()
	go this.heartbeatLoop()
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
	if err := this.ctx.Err(); err != nil {
		return 0, err
	}
	if len(this.pending) == 0 {
		select {
		case <-this.ctx.Done():
			return 0, this.ctx.Err()
		case next, open := <-this.input:
			if err := this.ctx.Err(); err != nil {
				return 0, err
			}
			if !open {
				return 0, io.EOF
			}
			this.pending = next
		}
	}
	n := copy(data, this.pending)
	this.pending = this.pending[n:]
	return n, nil
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
	if this.outputClosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(data) > 0 {
		if err := this.ctx.Err(); err != nil {
			return written, err
		}
		// Keep the allocation bound explicit, including for static range analysis.
		n := len(data)
		if n > webTerminalMessageLimit-1 {
			n = webTerminalMessageLimit - 1
		}
		message := make([]byte, n+1)
		message[0] = channel
		copy(message[1:], data[:n])
		if err := this.socket.SetWriteDeadline(time.Now().Add(this.timings.write)); err != nil {
			_ = this.Close()
			return written, err
		}
		if err := this.socket.WriteMessage(websocket.BinaryMessage, message); err != nil {
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
	if err := this.status(struct {
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
	defer func() {
		if !eof {
			close(this.input)
		}
	}()
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
			select {
			case this.input <- data:
			case <-this.ctx.Done():
				return
			default:
				return
			}
		case websocket.TextMessage:
			if len(data) > 1024 {
				return
			}
			values, err := webTerminalObject(data, "type", "columns", "rows", "widthPixels", "heightPixels", "signal")
			if err != nil {
				return
			}
			control, err := webTerminalString(values, "type", true)
			if err != nil {
				return
			}
			switch control {
			case "eof":
				if eof || len(values) != 1 {
					return
				}
				close(this.input)
				eof = true
			case "resize":
				if !this.open.hasPty {
					return
				}
				if _, exists := values["signal"]; exists {
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
	ticker := time.NewTicker(this.timings.ping)
	defer ticker.Stop()
	for {
		select {
		case <-this.ctx.Done():
			return
		case <-ticker.C:
			this.pingMutex.Lock()
			if this.awaitingPong != "" {
				this.pingMutex.Unlock()
				continue
			}
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				this.pingMutex.Unlock()
				return
			}
			payload := hex.EncodeToString(nonce[:])
			this.awaitingPong = payload
			this.pingMutex.Unlock()
			if err := this.socket.WriteControl(websocket.PingMessage, []byte(payload), time.Now().Add(this.timings.write)); err != nil {
				return
			}
		}
	}
}
