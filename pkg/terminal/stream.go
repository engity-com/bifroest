// Package terminal defines transport-independent execution I/O. It deliberately
// has no dependency on SSH, server connections, operating systems or processes.
package terminal

import (
	"context"
	"io"
)

type Window struct {
	Width, Height, WidthPixels, HeightPixels int
}

type Pty struct {
	Term          string
	Window        Window
	TerminalModes map[uint8]uint32
}

// Signal is a symbolic process signal (for example TERM), not a native number.
// The target backend validates and maps it for the target operating system.
type Signal string

// Stream belongs to one execution, never a persistent session or a reattachable
// terminal. EOF on Read is input half-close, not cancellation. Close must unblock
// pending I/O and cancel the execution context. CloseWrite finishes output without
// discarding pending input. Implementations must bound their queues and writes.
// Pty returns a stable initial snapshot and one execution-owned resize stream.
// Signals(nil) unregisters and drains sends before returning; receivers own their
// channels. Implementations must not close a registered signal receiver.
type Stream interface {
	io.ReadWriteCloser
	Context() context.Context
	CloseWrite() error
	Stderr() io.ReadWriter
	RawCommand() string
	Environ() []string
	Pty() (Pty, <-chan Window, bool)
	Signals(chan<- Signal)
}

func ClonePty(value Pty) Pty {
	if value.TerminalModes != nil {
		modes := make(map[uint8]uint32, len(value.TerminalModes))
		for key, setting := range value.TerminalModes {
			modes[key] = setting
		}
		value.TerminalModes = modes
	}
	return value
}
