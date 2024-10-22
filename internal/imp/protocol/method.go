package protocol

import (
	"context"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/errors"
)

type Method uint8

const (
	MethodPing Method = iota
	MethodKill
	MethodTcpForward
	MethodNamedPipe
)

var (
	ErrIllegalMethod = errors.System.Newf("Illegal protocol method")
)

func (this Method) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *Method) DecodeMsgpack(dec *msgpack.Decoder) error {
	return this.DecodeMsgPack(dec)
}

func (this Method) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeUint8(uint8(this)); err != nil {
		return err
	}
	return nil
}

func (this *Method) DecodeMsgPack(dec codec.MsgPackDecoder) error {
	plain, err := dec.DecodeUint8()
	if err != nil {
		return err
	}
	buf := Method(plain)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this Method) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Method) String() string {
	v, ok := protocolMethodToString[this]
	if !ok {
		return fmt.Sprintf("illegal-method-%d", this)
	}
	return v
}

func (this Method) MarshalText() ([]byte, error) {
	v, ok := protocolMethodToString[this]
	if !ok {
		return nil, errors.System.Newf("%w: %d", ErrIllegalMethod, this)
	}
	return []byte(v), nil
}

var (
	stringToProtocolMethod = map[string]Method{
		"ping":       MethodPing,
		"kill":       MethodKill,
		"tcpForward": MethodTcpForward,
		"namedPipe":  MethodNamedPipe,
	}
	protocolMethodToString = func(in map[string]Method) map[Method]string {
		result := make(map[Method]string, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(stringToProtocolMethod)
)

func handleFromServerSide[
	REQ any, REQP interface {
		DecodeMsgPack(dec codec.MsgPackDecoder) error
		*REQ
	},
	RSP codec.MsgPackCustomEncoder,
](_ context.Context, header *Header, conn codec.MsgPackConn, action func(REQP) RSP) error {
	fail := func(err error) error {
		return errors.Network.Newf("handling %v failed: %w", header.Method, err)
	}

	var req REQP = new(REQ)
	if err := req.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}

	rsp := action(req)

	if err := rsp.EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	return nil
}

func handleFromClientSide[
	RSP any, RSPP interface {
		DecodeMsgPack(dec codec.MsgPackDecoder) error
		*RSP
	},
	REQ codec.MsgPackCustomEncoder,
](_ context.Context, header *Header, conn codec.MsgPackConn, req REQ, action func(RSPP) error) error {
	fail := func(err error) error {
		return errors.Network.Newf("handling %v failed: %w", header.Method, err)
	}

	if err := req.EncodeMsgPack(conn); err != nil {
		return fail(err)
	}

	var rsp RSPP = new(RSP)
	if err := rsp.DecodeMsgPack(conn); err != nil {
		return fail(err)
	}

	return action(rsp)
}
