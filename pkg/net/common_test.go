package net

import (
	"io"
	"sync/atomic"
)

func toClosingReader[D io.Reader](delegate D, customizers ...func(*closingReader[D])) *closingReader[D] {
	result := &closingReader[D]{delegate: delegate}
	for _, customizer := range customizers {
		customizer(result)
	}
	return result
}

type closingReader[D io.Reader] struct {
	delegate D
	closed   atomic.Bool
	error    error
}

func (this *closingReader[D]) Read(p []byte) (n int, err error) {
	if this.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if v := this.error; v != nil {
		return 0, v
	}
	return this.delegate.Read(p)
}

func (this *closingReader[D]) Close() error {
	this.closed.Store(true)
	return nil
}

func (this *closingReader[D]) isClosed() bool {
	return this.closed.Load()
}

func toClosingWriter[D io.Writer](delegate D, customizers ...func(*closingWriter[D])) *closingWriter[D] {
	result := &closingWriter[D]{delegate: delegate}
	for _, customizer := range customizers {
		customizer(result)
	}
	return result
}

type closingWriter[D io.Writer] struct {
	delegate D
	closed   atomic.Bool
	error    error
}

func (this *closingWriter[D]) Write(p []byte) (n int, err error) {
	if this.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if v := this.error; v != nil {
		return 0, v
	}
	return this.delegate.Write(p)
}

func (this *closingWriter[D]) Close() error {
	this.closed.Store(true)
	return nil
}

func (this *closingWriter[D]) isClosed() bool {
	return this.closed.Load()
}

type someAddr string

func (someAddr) Network() string     { return "someAddr" }
func (this someAddr) String() string { return string(this) }
