package protocol

import (
	"context"
	"os"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
)

type methodExitRequest struct {
	exitCode int
}

func (this methodExitRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodExitRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodExitRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeInt(int64(this.exitCode)); err != nil {
		return err
	}
	return nil
}

func (this *methodExitRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.exitCode, err = dec.DecodeInt(); err != nil {
		return err
	}
	return nil
}

type methodExitResponse struct {
	error error
}

func (this methodExitResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodExitResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodExitResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodExitResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodExit(ctx context.Context, header *Header, _ log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodExitRequest) methodExitResponse {
		os.Exit(req.exitCode)
		return methodExitResponse{}
	})
}

func (this *Master) methodExit(ctx context.Context, ref Ref, connectionId connection.Id, exitCode int) error {
	return this.do(ctx, ref, connectionId, MethodExit, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodExitRequest{
			exitCode: exitCode,
		}, func(v *methodExitResponse) error {
			return v.error
		})
	})
}
