package protocol

import (
	"context"
	"os"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type methodGetEnvironmentRequest struct{}

func (this methodGetEnvironmentRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodGetEnvironmentRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodGetEnvironmentRequest) EncodeMsgPack(codec.MsgPackEncoder) error {
	return nil
}

func (this *methodGetEnvironmentRequest) DecodeMsgPack(codec.MsgPackDecoder) (err error) {
	return nil
}

type methodGetEnvironmentResponse struct {
	variables sys.EnvVars
	error     error
}

func (this methodGetEnvironmentResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodGetEnvironmentResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodGetEnvironmentResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeInt(int64(len(this.variables))); err != nil {
		return err
	}
	for k, v := range this.variables {
		if err := enc.EncodeString(k); err != nil {
			return err
		}
		if err := enc.EncodeString(v); err != nil {
			return err
		}
	}

	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodGetEnvironmentResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	numberOfVariables, err := dec.DecodeInt()
	if err != nil {
		return err
	}
	this.variables = make(map[string]string, numberOfVariables)
	for i := 0; i < numberOfVariables; i++ {
		k, err := dec.DecodeString()
		if err != nil {
			return err
		}
		v, err := dec.DecodeString()
		if err != nil {
			return err
		}
		this.variables[k] = v
	}

	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodGetEnvironment(ctx context.Context, header *Header, _ log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodGetEnvironmentRequest) methodGetEnvironmentResponse {
		var result methodGetEnvironmentResponse
		result.variables.Add(os.Environ()...)
		return result
	})
}

func (this *Master) methodGetEnvironment(ctx context.Context, ref Ref, connectionId connection.Id) (result sys.EnvVars, _ error) {
	if err := this.do(ctx, ref, connectionId, MethodGetEnvironment, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodGetEnvironmentRequest{}, func(v *methodGetEnvironmentResponse) error {
			result = v.variables
			return errors.AsRemoteError(v.error)
		})
	}); err != nil {
		return nil, err
	}
	return result, nil
}
