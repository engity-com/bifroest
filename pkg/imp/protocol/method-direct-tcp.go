package protocol

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func newMethodDirectTcpRequest(host string, port uint32) *methodDirectTcpRequest {
	return &methodDirectTcpRequest{
		host,
		port,
	}
}

type methodDirectTcpRequest struct {
	host string
	port uint32
}

func (this methodDirectTcpRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeString(this.host); err != nil {
		return err
	}
	if err := enc.EncodeUint32(this.port); err != nil {
		return err
	}
	return nil
}

func (this *methodDirectTcpRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.host, err = dec.DecodeString(); err != nil {
		return err
	}
	if this.port, err = dec.DecodeUint32(); err != nil {
		return err
	}
	return nil
}

func handleMethodDirectTcpInitFromServerSide(conn io.ReadWriter) (host string, port uint32, _ error) {
	fail := func(err error) (string, uint32, error) {
		return "", 0, errors.Network.Newf("direct tcp helo failed: %w", err)
	}

	var req methodDirectTcpRequest
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return fail(err)
	}

	return req.host, req.port, nil
}

func handleMethodDirectTcpInitFromClientSide(host string, port uint32, conn io.ReadWriter) error {
	fail := func(err error) error {
		return errors.Network.Newf("direct tcp helo failed: %w", err)
	}

	req := newMethodDirectTcpRequest(host, port)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Server) parseAndHandleMethodDirectTcp(ctx context.Context, conn Conn) error {
	host, port, err := handleMethodDirectTcpInitFromServerSide(conn)
	if err != nil {
		return err
	}
	return this.serveMethodDirectTcp(ctx, host, port, conn)
}

func (this *Server) serveMethodDirectTcp(ctx context.Context, host string, port uint32, conn Conn) error {
	fail := func(err error) error {
		return errors.Network.Newf("direct tcp failed: %w", err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Network.Newf(msg, args...))
	}

	dest := net.JoinHostPort(host, strconv.FormatInt(int64(port), 10))

	destination, err := this.dialer().DialContext(ctx, "tcp", dest)
	if err != nil {
		return failf("cannot establish ")
	}
	defer common.IgnoreCloseError(destination)

	l := conn.Logger("direct-tcp").
		With("destHost", host).
		With("destPort", port)

	nameOf := func(isL2r bool) string {
		if isL2r {
			return "source -> destination"
		}
		return "destination -> source"
	}

	return sys.FullDuplexCopy(ctx, conn, destination, &sys.FullDuplexCopyOpts{
		OnStart: func() {
			l.Debug("port forwarding started")
		},
		OnEnd: func(s2d, d2s int64, duration time.Duration, err error, wasInL2r *bool) {
			ld := l.
				With("s2d", s2d).
				With("d2s", d2s).
				With("duration", duration)
			if wasInL2r != nil {
				ld = ld.With("direction", nameOf(*wasInL2r))
			}

			if err != nil {
				ld.WithError(err).Error("cannot successful handle port forwarding request; canceling...")
			} else {
				ld.Debug("port forwarding finished")
			}
		},
		OnStreamEnd: func(isL2r bool, err error) {
			name := "source -> destination"
			if !isL2r {
				name = "destination -> source"
			}
			l.WithError(err).Tracef("coping of %s done", name)
		},
	})
}

func (this *ClientSession) initiateMethodDirectTcp(connectionId uuid.UUID, host string, port uint32) (_ net.Conn, rErr error) {
	return this.doAndReturn(MethodDirectTcp, connectionId, func(conn net.Conn) error {
		return handleMethodDirectTcpInitFromClientSide(host, port, conn)
	})
}
