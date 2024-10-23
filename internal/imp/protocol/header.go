package protocol

import (
	"context"
	"fmt"
	"io"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
)

const (
	HeaderMagic = 183
)

type Header struct {
	Method       Method
	ConnectionId connection.Id
}

func (this *Header) DecodeMsgpack(dec *msgpack.Decoder) error {
	return this.DecodeMsgPack(dec)
}

func (this Header) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this Header) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if n, err := enc.Writer().Write([]byte{HeaderMagic}); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	if err := this.Method.EncodeMsgPack(enc); err != nil {
		return err
	}
	if err := this.ConnectionId.EncodeMsgPack(enc); err != nil {
		return err
	}
	return nil
}

func (this *Header) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	hmb := make([]byte, 1)

	if n, err := dec.Buffered().Read(hmb); err != nil {
		return err
	} else if n != 1 {
		return io.ErrUnexpectedEOF
	} else if hmb[0] != HeaderMagic {
		return fmt.Errorf("header magic number is invalid - expected %d, got %d", HeaderMagic, hmb[0])
	}
	if err := this.Method.DecodeMsgPack(dec); err != nil {
		return err
	}
	if err := this.ConnectionId.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *Master) do(ctx context.Context, ref Ref, connectionId connection.Id, method Method, action func(*Header, codec.MsgPackConn) error) (rErr error) {
	fail := func(err error) error {
		return err
	}

	conn, err := this.DialContextWithMsgPack(ctx, ref)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, conn)

	header := Header{
		Method:       method,
		ConnectionId: connectionId,
	}
	if err := header.EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	if err := action(&header, conn); err != nil {
		return fail(err)
	}

	return nil
}
