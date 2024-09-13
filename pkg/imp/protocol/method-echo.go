package protocol

import (
	"context"
	"io"
	"net"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/errors"
)

func newMethodEchoRequest(msg string) *methodEchoRequest {
	return &methodEchoRequest{
		msg,
	}
}

type methodEchoRequest struct {
	msg string
}

func (this methodEchoRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeString(this.msg); err != nil {
		return err
	}
	return nil
}

func (this *methodEchoRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.msg, err = dec.DecodeString(); err != nil {
		return err
	}
	return nil
}

func newMethodEchoResponse(msg string) *methodEchoResponse {
	return &methodEchoResponse{
		msg,
	}
}

type methodEchoResponse struct {
	msg string
}

func (this methodEchoResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeString(this.msg); err != nil {
		return err
	}
	return nil
}

func (this *methodEchoResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.msg, err = dec.DecodeString(); err != nil {
		return err
	}
	return nil
}

func handleMethodEchoFromServerSide(conn io.ReadWriter, answerer func(string) string) (msg string, _ error) {
	fail := func(err error) (string, error) {
		return "", errors.Network.Newf("parse echo request failed: %w", err)
	}

	var req methodEchoRequest
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		return fail(err)
	}

	rsp := newMethodEchoResponse(answerer(req.msg))
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(rsp); err != nil {
		return fail(err)
	}

	return req.msg, nil
}

func handleMethodEchoFromClientSide(msg string, conn io.ReadWriter) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.Network.Newf("send echo request failed: %w", err)
	}

	req := newMethodEchoRequest(msg)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return fail(err)
	}

	var rsp methodEchoResponse
	dec := msgpack.NewDecoder(conn)
	if err := dec.Decode(&rsp); err != nil {
		return fail(err)
	}

	return rsp.msg, nil
}

func (this *Server) parseAndHandleMethodEcho(_ context.Context, conn Conn) error {
	msg, err := handleMethodEchoFromServerSide(conn, func(s string) string {
		return "thanks for: " + s
	})
	if err != nil {
		return err
	}
	conn.Logger("echo").
		With("fromRemote", msg).
		Info("received echo")

	return nil
}

func (this *ClientSession) methodEcho(connectionId uuid.UUID, msg string) (rsp string, err error) {
	err = this.do(MethodEcho, connectionId, func(conn net.Conn) error {
		var lErr error
		rsp, lErr = handleMethodEchoFromClientSide(msg, conn)
		return lErr
	})
	return rsp, err
}
