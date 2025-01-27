package protocol

import (
	"bytes"
	"context"
	goos "os"
	"path/filepath"
	"strconv"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type methodGetConnectionExitCodeRequest struct{}

func (this methodGetConnectionExitCodeRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodGetConnectionExitCodeRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodGetConnectionExitCodeRequest) EncodeMsgPack(codec.MsgPackEncoder) error {
	return nil
}

func (this *methodGetConnectionExitCodeRequest) DecodeMsgPack(codec.MsgPackDecoder) (err error) {
	return nil
}

type methodGetConnectionExitCodeResponse struct {
	found    bool
	exitCode int
	error    error
}

func (this methodGetConnectionExitCodeResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodGetConnectionExitCodeResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodGetConnectionExitCodeResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeBool(this.found); err != nil {
		return err
	}
	if err := enc.EncodeInt(int64(this.exitCode)); err != nil {
		return err
	}
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodGetConnectionExitCodeResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.found, err = dec.DecodeBool(); err != nil {
		return err
	}
	if this.exitCode, err = dec.DecodeInt(); err != nil {
		return err
	}
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodGetConnectionExitCode(ctx context.Context, header *Header, _ log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodGetConnectionExitCodeRequest) methodGetConnectionExitCodeResponse {
		rsp := methodGetConnectionExitCodeResponse{}
		if !header.ConnectionId.IsZero() {
			fn := filepath.Join(this.ExitCodeByConnectionIdPath, header.ConnectionId.String())
			b, err := goos.ReadFile(fn)
			if sys.IsNotExist(err) {
				rsp.found = false
			} else if err != nil {
				rsp.error = err
			} else if v, err := strconv.Atoi(string(bytes.TrimSpace(b))); err != nil {
				rsp.found = false
			} else {
				rsp.found = true
				rsp.exitCode = v
			}
		}
		return rsp
	})
}

func (this *Master) methodGetConnectionExitCode(ctx context.Context, ref Ref, connectionId connection.Id) (result int, _ error) {
	if err := this.do(ctx, ref, connectionId, MethodGetConnectionExitCode, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodGetConnectionExitCodeRequest{}, func(v *methodGetConnectionExitCodeResponse) error {
			if err := v.error; err != nil {
				return errors.AsRemoteError(err)
			}
			if !v.found {
				return connection.ErrNotFound
			}
			result = v.exitCode
			return nil
		})
	}); err != nil {
		return 0, err
	}

	return result, nil
}
