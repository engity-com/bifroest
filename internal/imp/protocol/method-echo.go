package protocol

import (
	"context"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
)

type methodEchoRequest struct {
	msg string
}

func (this methodEchoRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodEchoRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodEchoRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeString(this.msg); err != nil {
		return err
	}
	return nil
}

func (this *methodEchoRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.msg, err = dec.DecodeString(); err != nil {
		return err
	}
	return nil
}

type methodEchoResponse struct {
	msg   string
	error error
}

func (this methodEchoResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodEchoResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodEchoResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeString(this.msg); err != nil {
		return err
	}
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodEchoResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.msg, err = dec.DecodeString(); err != nil {
		return err
	}
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodEcho(ctx context.Context, header *Header, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodEchoRequest) methodEchoResponse {
		return methodEchoResponse{msg: "thanks for: " + req.msg}
	})
}

func (this *Master) methodEcho(ctx context.Context, ref Ref, connectionId connection.Id, msg string) (rsp string, err error) {
	err = this.do(ctx, ref, connectionId, MethodEcho, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodEchoRequest{
			msg: msg,
		}, func(v *methodEchoResponse) error {
			rsp = v.msg
			return v.error
		})
	})
	return rsp, err
}
