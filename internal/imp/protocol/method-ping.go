package protocol

import (
	"context"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
)

type methodPingRequest struct{}

func (this methodPingRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodPingRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodPingRequest) EncodeMsgPack(codec.MsgPackEncoder) error {
	return nil
}

func (this *methodPingRequest) DecodeMsgPack(codec.MsgPackDecoder) (err error) {
	return nil
}

type methodPingResponse struct {
	error error
}

func (this methodPingResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodPingResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodPingResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodPingResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodPing(ctx context.Context, header *Header, _ log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodPingRequest) methodPingResponse {
		return methodPingResponse{}
	})
}

func (this *Master) methodPing(ctx context.Context, ref Ref, connectionId connection.Id) error {
	return this.do(ctx, ref, connectionId, MethodPing, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodPingRequest{}, func(v *methodPingResponse) error {
			return errors.AsRemoteError(v.error)
		})
	})
}
