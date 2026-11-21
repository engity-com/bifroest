package https

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
)

// ConnectionObservation receives fixed lifecycle events, never remote addresses,
// TLS names or diagnostics. The callback must be concurrency-safe and nonblocking.
type ConnectionObservation func(event string)

type observedListener struct {
	net.Listener
	observe func() ConnectionObservation
}

func (l observedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &observedConnection{Conn: c, observe: l.observe()}, nil
}

type observedConnection struct {
	net.Conn
	once    sync.Once
	observe ConnectionObservation
}

func (c *observedConnection) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.failure(err)
	return n, err
}
func (c *observedConnection) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.failure(err)
	return n, err
}
func (c *observedConnection) failure(err error) {
	if err == nil || c.observe == nil {
		return
	}
	var timeout net.Error
	switch {
	case errors.As(err, &timeout) && timeout.Timeout():
		c.observe("timeout")
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		c.observe("peer_closed")
	case !errors.Is(err, net.ErrClosed):
		c.observe("io_error")
	}
}
func (c *observedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.observe != nil {
			c.observe("closed")
		}
	})
	return err
}

func observeConnectionState(c net.Conn, state http.ConnState) {
	if state != http.StateActive && state != http.StateIdle && state != http.StateClosed {
		return
	}
	if tlsConn, ok := c.(*tls.Conn); ok {
		if raw, ok := tlsConn.NetConn().(*observedConnection); ok && raw.observe != nil {
			if tlsConn.ConnectionState().HandshakeComplete {
				raw.observe("handshake_complete")
			} else if state == http.StateClosed {
				raw.observe("handshake_aborted")
			}
		}
	}
}
