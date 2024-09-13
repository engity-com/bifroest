package protocol

import (
	"context"
	"io"
	"net"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/errors"
)

func newMethodAgentForwardResponse(socketPath string) *methodAgentForwardResponse {
	return &methodAgentForwardResponse{
		socketPath,
	}
}

type methodAgentForwardResponse struct {
	socketPath string
}

func (this methodAgentForwardResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	if err := enc.EncodeString(this.socketPath); err != nil {
		return err
	}
	return nil
}

func (this *methodAgentForwardResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	if this.socketPath, err = dec.DecodeString(); err != nil {
		return err
	}
	return nil
}

func handleMethodAgentForwardInitFromServerSide(socketPath string, conn io.ReadWriter) error {
	fail := func(err error) error {
		return errors.Network.Newf("agent forward helo failed: %w", err)
	}

	rsp := newMethodAgentForwardResponse(socketPath)
	enc := msgpack.NewEncoder(conn)
	if err := enc.Encode(rsp); err != nil {
		return fail(err)
	}

	return nil
}

func handleMethodAgentForwardInitFromClientSide(from io.Reader) (socketPath string, _ error) {
	fail := func(err error) (string, error) {
		return "", errors.Network.Newf("agent forward helo failed: %w", err)
	}

	var rsp methodAgentForwardResponse
	dec := msgpack.NewDecoder(from)
	if err := dec.Decode(&rsp); err != nil {
		return fail(err)
	}

	return rsp.socketPath, nil
}

func (this *Server) parseAndHandleMethodAgentForward(ctx context.Context, conn Conn) error {
	var socketPath string = ""               // TODO! Resolve this one!
	var localSocket io.ReadWriteCloser = nil // TODO! Resolve this one!

	err := handleMethodAgentForwardInitFromServerSide(socketPath, conn)
	if err != nil {
		return err
	}

	return this.serveMethodAgentForward(ctx, conn, localSocket)
}

func (this *Server) serveMethodAgentForward(ctx context.Context, conn Conn, localSocket io.ReadWriter) error {
	panic("not implemented") // TODO! Implement
}

func (this *ClientSession) initiateMethodAgentForward(connectionId uuid.UUID) (conn net.Conn, socketPath string, err error) {
	conn, err = this.doAndReturn(MethodAgentForward, connectionId, func(conn net.Conn) error {
		var lErr error
		socketPath, lErr = handleMethodAgentForwardInitFromClientSide(conn)
		return lErr
	})
	return conn, socketPath, err
}
