package protocol

import (
	"context"

	log "github.com/echocat/slf4g"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	ErrNoSuchProcess = errors.System.Newf("no such process")
)

type methodKillRequest struct {
	pid    int
	signal sys.Signal
}

func (this methodKillRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodKillRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodKillRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeInt(int64(this.pid)); err != nil {
		return err
	}
	if err := this.signal.EncodeMsgPack(enc); err != nil {
		return err
	}
	return nil
}

func (this *methodKillRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.pid, err = dec.DecodeInt(); err != nil {
		return err
	}
	if err = this.signal.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

type methodKillResponse struct {
	error error
}

func (this methodKillResponse) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodKillResponse) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodKillResponse) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := errors.EncodeMsgPack(this.error, enc); err != nil {
		return err
	}
	return nil
}

func (this *methodKillResponse) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.error, err = errors.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

func (this *imp) handleMethodKill(ctx context.Context, header *Header, _ log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodKillRequest) methodKillResponse {
		pid := req.pid
		fail := func(err error) methodKillResponse {
			return methodKillResponse{errors.System.Newf("cannot kill process %d of %v with %v: %w", pid, header.ConnectionId, req.signal, err)}
		}

		if pid == 0 {
			expectedEnv := connection.EnvName + "=" + header.ConnectionId.String()
			candidates, err := process.ProcessesWithContext(ctx)
			if err != nil {
				return fail(err)
			}
			for _, candidate := range candidates {
				envs, err := candidate.Environ()
				if err != nil || len(envs) == 0 {
					continue
				}
				for _, env := range envs {
					if env == expectedEnv {
						pid = int(candidate.Pid)
						break
					}
				}
				if pid != 0 {
					break
				}
			}
		}
		if pid == 0 {
			return methodKillResponse{ErrNoSuchProcess}
		}

		if err := this.kill(ctx, pid, req.signal); err != nil {
			return fail(err)
		}

		return methodKillResponse{}
	})
}

func (this *Master) methodKill(ctx context.Context, ref Ref, connectionId connection.Id, pid int, signal sys.Signal) error {
	return this.do(ctx, ref, connectionId, MethodKill, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodKillRequest{
			pid:    pid,
			signal: signal,
		}, func(v *methodKillResponse) error {
			return errors.AsRemoteError(v.error)
		})
	})
}
