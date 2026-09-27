package protocol

import (
	"bytes"
	"context"
	"encoding/binary"
	stderrors "errors"
	"fmt"
	"io"
	gonet "net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/xtaci/smux"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type reverseTCPRequest struct {
	host string
	port uint16
}

func (r reverseTCPRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeString(r.host); err != nil {
		return err
	}
	return enc.EncodeUint16(r.port)
}

func (r *reverseTCPRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if r.host, err = dec.DecodeString(); err != nil {
		return err
	}
	r.port, err = dec.DecodeUint16()
	return err
}

type reverseTCPResponse struct {
	addr string
	err  error
}

func (r reverseTCPResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeString(r.addr); err != nil {
		return err
	}
	return errors.EncodeMsgPack(r.err, enc)
}

func (r *reverseTCPResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if r.addr, err = dec.DecodeString(); err != nil {
		return err
	}
	r.err, err = errors.DecodeMsgPack(dec)
	return err
}

func (this *imp) handleMethodListenReverseTCP(ctx context.Context, header *Header, logger log.Logger, conn codec.MsgPackConn) error {
	fail := func(err error) error {
		return errors.Network.Newf("handling %v failed: %w", header.Method, err)
	}
	var req reverseTCPRequest
	if err := req.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}
	if err := validateReverseTCPHost(req.host); err != nil {
		if e := (reverseTCPResponse{err: err}).EncodeMsgPack(conn); e != nil {
			return fail(e)
		}
		return nil
	}
	// An omitted SSH bind host is loopback; only an explicit * requests a wildcard bind.
	host := req.host
	switch host {
	case "":
		host = "localhost"
	case "*":
		host = ""
	}
	addr := gonet.JoinHostPort(host, strconv.Itoa(int(req.port)))
	ln, err := gonet.Listen("tcp", addr)
	if err != nil {
		if e := (reverseTCPResponse{err: reWrapIfUserFacingNetworkErrors(err)}).EncodeMsgPack(conn); e != nil {
			return fail(e)
		}
		logger.WithError(err).Infof("cannot listen to %s", addr)
		return nil
	}
	defer common.IgnoreCloseError(ln)
	if err := (reverseTCPResponse{addr: ln.Addr().String()}).EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	mux, err := smux.Client(conn, baseNamedPipeConfig())
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseError(mux)
	stop := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		_ = mux.Close()
	})
	defer stop()

	for {
		tcpConn, err := ln.Accept()
		if sys.IsClosedError(err) || ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return fail(err)
		}
		go func() {
			defer common.IgnoreCloseError(tcpConn)
			stream, err := mux.OpenStream()
			if err != nil {
				logger.WithError(err).Debug("cannot open reverse TCP stream")
				return
			}
			defer common.IgnoreCloseError(stream)
			if err := writeReverseTCPAddresses(stream, tcpConn.RemoteAddr(), tcpConn.LocalAddr()); err != nil {
				logger.WithError(err).Warn("cannot send reverse TCP addresses")
				return
			}
			stopCopy := context.AfterFunc(ctx, func() {
				_ = tcpConn.Close()
				_ = stream.Close()
			})
			defer stopCopy()
			upDone := make(chan error, 1)
			framed := &reverseTCPConn{stream: stream}
			go func() {
				_, e := io.Copy(framed, tcpConn)
				if stderrors.Is(e, io.EOF) {
					e = nil
				}
				if e == nil {
					e = framed.CloseWrite()
				}
				if e != nil {
					_ = stream.Close()
					_ = tcpConn.Close()
				}
				upDone <- e
			}()
			_, downErr := io.Copy(tcpConn, framed)
			if stderrors.Is(downErr, io.EOF) {
				downErr = nil
			}
			if downErr == nil {
				downErr = tcpConn.(*gonet.TCPConn).CloseWrite()
			}
			if downErr != nil {
				_ = stream.Close()
				_ = tcpConn.Close()
			}
			upErr := <-upDone
			if ctx.Err() == nil && (upErr != nil || downErr != nil) {
				logger.With("upError", upErr).With("downError", downErr).Debug("reverse TCP stream failed")
			}
		}()
	}
}

func (this *Master) methodListenReverseTCP(ctx, sessionCtx context.Context, ref Ref, connectionId connection.Id, host string, port uint16) (gonet.Listener, error) {
	fail := func(err error) (gonet.Listener, error) {
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if sessionCtx.Err() != nil {
			err = sessionCtx.Err()
		}
		return nil, errors.Network.Newf("handling %v on %s failed: %w", MethodListenReverseTCP, gonet.JoinHostPort(host, strconv.Itoa(int(port))), err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := sessionCtx.Err(); err != nil {
		return fail(err)
	}
	if err := validateReverseTCPHost(host); err != nil {
		return fail(err)
	}
	dialCtx, cancelDial := context.WithCancel(ctx)
	stopSessionDial := context.AfterFunc(sessionCtx, cancelDial)
	conn, err := this.DialContextWithMsgPack(dialCtx, ref)
	stopSessionDial()
	cancelDial()
	if err != nil {
		return fail(err)
	}
	success := false
	defer common.IgnoreCloseErrorIfFalse(&success, conn)
	stopRequestDuringSetup := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopRequestDuringSetup()
	stopSessionDuringSetup := context.AfterFunc(sessionCtx, func() { _ = conn.Close() })
	defer stopSessionDuringSetup()
	if err := (Header{MethodListenReverseTCP, connectionId}).EncodeMsgPack(conn); err != nil {
		return fail(err)
	}
	if err := (reverseTCPRequest{host, port}).EncodeMsgPack(conn); err != nil {
		return fail(err)
	}
	var rsp reverseTCPResponse
	if err := rsp.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}
	if rsp.err != nil {
		return fail(errors.AsRemoteError(rsp.err))
	}
	parsed, err := netip.ParseAddrPort(rsp.addr)
	if err != nil || parsed.Port() == 0 {
		return fail(fmt.Errorf("invalid reverse TCP listener address %q", rsp.addr))
	}
	mux, err := smux.Server(conn, baseNamedPipeConfig())
	if err != nil {
		return fail(err)
	}
	ln := &reverseTCPListener{conn: conn, mux: mux, addr: gonet.TCPAddrFromAddrPort(parsed)}
	stopRequest := context.AfterFunc(ctx, func() { _ = ln.Close() })
	stopSession := context.AfterFunc(sessionCtx, func() { _ = ln.Close() })
	ln.closeMu.Lock()
	if ln.closed {
		stopRequest()
		stopSession()
	} else {
		ln.stopRequest = stopRequest
		ln.stopSession = stopSession
	}
	ln.closeMu.Unlock()
	stopRequestDuringSetup()
	stopSessionDuringSetup()
	if ctx.Err() != nil || sessionCtx.Err() != nil {
		_ = ln.Close()
		return fail(context.Canceled)
	}
	success = true
	return ln, nil
}

func validateReverseTCPHost(host string) error {
	if strings.ContainsRune(host, 0) {
		return fmt.Errorf("invalid TCP listen host %q: contains NUL", host)
	}
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid TCP listen host %q: %w", host, err)
		}
	}
	return nil
}

type reverseTCPListener struct {
	conn        codec.MsgPackConn
	mux         *smux.Session
	addr        *gonet.TCPAddr
	once        sync.Once
	closeMu     sync.Mutex
	closed      bool
	stopRequest func() bool
	stopSession func() bool
}

func (l *reverseTCPListener) Accept() (gonet.Conn, error) {
	stream, err := l.mux.AcceptStream()
	if err != nil {
		return nil, err
	}
	remote, local, err := readReverseTCPAddresses(stream)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &reverseTCPConn{stream: stream, remote: remote, local: local}, nil
}

func (l *reverseTCPListener) Close() error {
	l.once.Do(func() {
		l.closeMu.Lock()
		l.closed = true
		if l.stopRequest != nil {
			l.stopRequest()
		}
		if l.stopSession != nil {
			l.stopSession()
		}
		l.closeMu.Unlock()
		_ = l.mux.Close()
		_ = l.conn.Close()
	})
	return nil
}

func (l *reverseTCPListener) Addr() gonet.Addr { return l.addr }

type reverseTCPConn struct {
	stream    *smux.Stream
	remote    *gonet.TCPAddr
	local     *gonet.TCPAddr
	writeMu   sync.Mutex
	stateMu   sync.Mutex
	readEOF   bool
	writeEOF  bool
	remaining uint16
}

func (c *reverseTCPConn) RemoteAddr() gonet.Addr             { return c.remote }
func (c *reverseTCPConn) LocalAddr() gonet.Addr              { return c.local }
func (c *reverseTCPConn) Close() error                       { return c.stream.Close() }
func (c *reverseTCPConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *reverseTCPConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *reverseTCPConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// Zero-length frames mark EOF. Payloads are bounded independently of smux's window.
const reverseTCPChunkSize = 16 * 1024

func (c *reverseTCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.remaining == 0 {
		if c.readEOF {
			return 0, io.EOF
		}
		var header [2]byte
		if _, err := io.ReadFull(c.stream, header[:]); err != nil {
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		c.remaining = binary.BigEndian.Uint16(header[:])
		if c.remaining > reverseTCPChunkSize {
			return 0, fmt.Errorf("invalid reverse TCP data frame length %d", c.remaining)
		}
		if c.remaining == 0 {
			c.stateMu.Lock()
			c.readEOF = true
			if c.writeEOF {
				_ = c.stream.Close()
			}
			c.stateMu.Unlock()
			return 0, io.EOF
		}
	}
	if len(p) > int(c.remaining) {
		p = p[:c.remaining]
	}
	n, err := io.ReadFull(c.stream, p)
	c.remaining -= uint16(n)
	return n, err
}

func (c *reverseTCPConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return 0, io.ErrClosedPipe
	}
	var frame [2 + reverseTCPChunkSize]byte
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > reverseTCPChunkSize {
			n = reverseTCPChunkSize
		}
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		copy(frame[2:], p[:n])
		count, err := c.stream.Write(frame[:n+2])
		if err == nil && count != n+2 {
			err = io.ErrShortWrite
		}
		if err != nil {
			_ = c.stream.Close()
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *reverseTCPConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOF {
		return nil
	}
	var eof [2]byte
	if n, err := c.stream.Write(eof[:]); err != nil {
		return err
	} else if n != len(eof) {
		return io.ErrShortWrite
	}
	c.stateMu.Lock()
	c.writeEOF = true
	if c.readEOF {
		_ = c.stream.Close()
	}
	c.stateMu.Unlock()
	return nil
}

// A length prefix prevents the decoder from consuming any bytes of the TCP payload.
func writeReverseTCPAddresses(w io.Writer, remote, local gonet.Addr) error {
	if remote.Network() != "tcp" || local.Network() != "tcp" {
		return fmt.Errorf("non-TCP reverse connection addresses")
	}
	data, err := msgpack.Marshal([2]string{remote.String(), local.String()})
	if err != nil {
		return err
	}
	if len(data) > 512 {
		return fmt.Errorf("reverse TCP address frame too large")
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(data)))
	_, err = io.Copy(w, bytes.NewReader(append(length[:], data...)))
	return err
}

func readReverseTCPAddresses(r io.Reader) (*gonet.TCPAddr, *gonet.TCPAddr, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 || n > 512 {
		return nil, nil, fmt.Errorf("invalid reverse TCP address frame length %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, nil, err
	}
	var addresses [2]string
	if err := msgpack.Unmarshal(data, &addresses); err != nil {
		return nil, nil, err
	}
	remote, err := netip.ParseAddrPort(addresses[0])
	if err != nil || remote.Port() == 0 {
		return nil, nil, fmt.Errorf("invalid reverse TCP remote address %q", addresses[0])
	}
	local, err := netip.ParseAddrPort(addresses[1])
	if err != nil || local.Port() == 0 {
		return nil, nil, fmt.Errorf("invalid reverse TCP local address %q", addresses[1])
	}
	return gonet.TCPAddrFromAddrPort(remote), gonet.TCPAddrFromAddrPort(local), nil
}
