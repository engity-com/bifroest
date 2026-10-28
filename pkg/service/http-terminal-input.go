package service

import (
	"context"
	"io"
	"sync"
)

const webTerminalInputBytes = webTerminalInputQueue * webTerminalMessageLimit

// The byte stream does not expose WebSocket message boundaries. Keep exactly
// the existing 64-KiB maximum, without allocating one queue slot per keystroke.
// A fixed ring also avoids slice growth or retained per-message allocations.
type webTerminalInputBuffer struct {
	mutex      sync.Mutex
	data       [webTerminalInputBytes]byte
	head, used int
	eof        bool
	wake       chan struct{}
}

func newWebTerminalInputBuffer() *webTerminalInputBuffer {
	return &webTerminalInputBuffer{wake: make(chan struct{}, 1)}
}

func (this *webTerminalInputBuffer) notify() {
	select {
	case this.wake <- struct{}{}:
	default:
	}
}

func (this *webTerminalInputBuffer) append(data []byte) bool {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.eof || len(data) > len(this.data)-this.used {
		return false
	}
	tail := (this.head + this.used) % len(this.data)
	n := copy(this.data[tail:], data)
	copy(this.data[:], data[n:])
	this.used += len(data)
	this.notify()
	return true
}

func (this *webTerminalInputBuffer) end() {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.eof = true
	this.notify()
}

func (this *webTerminalInputBuffer) read(ctx context.Context, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		this.mutex.Lock()
		if this.used != 0 {
			n := min(len(data), this.used)
			first := copy(data[:n], this.data[this.head:min(this.head+n, len(this.data))])
			copy(data[first:n], this.data[:n-first])
			clear(this.data[this.head:min(this.head+n, len(this.data))])
			clear(this.data[:n-first])
			this.head = (this.head + n) % len(this.data)
			this.used -= n
			this.mutex.Unlock()
			return n, nil
		}
		eof := this.eof
		this.mutex.Unlock()
		if eof {
			return 0, io.EOF
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-this.wake:
		}
	}
}
