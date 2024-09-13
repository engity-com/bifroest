package protocol

import (
	"context"
	"io"
	"net"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func newMethodKillRequest(pid int, signal uint8) *methodKillRequest {
	return &methodKillRequest{
		pid,
		signal,
	}
}

type methodKillRequest struct {
	pid    int
	signal uint8
}

func (this methodKillRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeInt(int64(this.pid)); err != nil {
		return err
	}
	if err := enc.EncodeUint8(this.signal); err != nil {
		return err
	}
	return nil
}

func (this *methodKillRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.pid, err = dec.DecodeInt(); err != nil {
		return err
	}
	if this.signal, err = dec.DecodeUint8(); err != nil {
		return err
	}
	return nil
}

func handleMethodKillFromServerSide(conn io.ReadWriter) (pid int, signal uint8, _ error) {
	fail := func(err error) (int, uint8, error) {
		return 0, 0, errors.Network.Newf("parse kill request failed: %w", err)
	}

	var req methodKillRequest
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return fail(err)
	}

	return req.pid, req.signal, nil
}

func handleMethodKillFromClientSide(pid int, signal uint8, conn io.ReadWriter) error {
	fail := func(err error) error {
		return errors.Network.Newf("send kill request failed: %w", err)
	}

	req := newMethodKillRequest(pid, signal)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Server) parseAndHandleMethodKill(ctx context.Context, conn Conn) error {
	pid, signal, err := handleMethodKillFromServerSide(conn)
	if err != nil {
		return err
	}
	return this.handleMethodKill(ctx, pid, signal)
}

func (this *Server) handleMethodKill(_ context.Context, pid int, plainSignal uint8) error {
	fail := func(err error) error {
		return errors.Network.Newf("kill failed: %w", err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	signal := sys.Signal(plainSignal)

	if err := this.kill(pid, signal); err != nil {
		return failf("cannot kill process #%d with %v: %w", pid, signal, err)
	}

	return nil
}

func (this *ClientSession) methodKill(connectionId uuid.UUID, pid int, signal sys.Signal) (rErr error) {
	return this.do(MethodKill, connectionId, func(conn net.Conn) error {
		return handleMethodKillFromClientSide(pid, uint8(signal), conn)
	})
}
