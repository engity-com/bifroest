package protocol

import (
	"context"
	"io"
	"net"
	"os"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/errors"
)

func newMethodExitRequest(exitCode int) *methodExitRequest {
	return &methodExitRequest{
		exitCode,
	}
}

type methodExitRequest struct {
	exitCode int
}

func (this methodExitRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeInt(int64(this.exitCode)); err != nil {
		return err
	}
	return nil
}

func (this *methodExitRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.exitCode, err = dec.DecodeInt(); err != nil {
		return err
	}
	return nil
}

func handleMethodExitFromServerSide(conn io.ReadWriter) (exitCode int, _ error) {
	fail := func(err error) (int, error) {
		return 0, errors.Network.Newf("parse exit request failed: %w", err)
	}

	var req methodExitRequest
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return fail(err)
	}

	return req.exitCode, nil
}

func handleMethodExitFromClientSide(exitCode int, conn io.ReadWriter) error {
	fail := func(err error) error {
		return errors.Network.Newf("send exit request failed: %w", err)
	}

	req := newMethodExitRequest(exitCode)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fail(err)
	}

	return nil
}

func (this *Server) parseAndHandleMethodExit(ctx context.Context, conn Conn) error {
	exitCode, err := handleMethodExitFromServerSide(conn)
	if err != nil {
		return err
	}
	return this.handleMethodExit(ctx, exitCode)
}

func (this *Server) handleMethodExit(_ context.Context, exitCode int) error {
	os.Exit(exitCode)
	return nil
}

func (this *ClientSession) methodExit(connectionId uuid.UUID, exitCode int) (rErr error) {
	return this.do(MethodExit, connectionId, func(conn net.Conn) error {
		return handleMethodExitFromClientSide(exitCode, conn)
	})
}
