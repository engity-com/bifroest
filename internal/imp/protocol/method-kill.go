package protocol

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

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

func (this *imp) handleMethodKill(ctx context.Context, header *Header, logger log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodKillRequest) methodKillResponse {
		fail := func(pid int, err error) methodKillResponse {
			return methodKillResponse{errors.System.Newf("cannot kill process %d of %v with %v: %w", pid, header.ConnectionId, req.signal, err)}
		}

		pids := []int{req.pid}
		if req.pid == 0 {
			pids = nil
			pidFn := filepath.Join(this.ExitCodeByConnectionIdPath, header.ConnectionId.String()+".pid")
			if plainPid, err := os.ReadFile(pidFn); err == nil {
				if pid, err := strconv.Atoi(string(plainPid)); err == nil && pid > 0 {
					pids = append(pids, pid)
				}
			}
		}
		if len(pids) == 0 {
			expectedEnv := connection.EnvName + "=" + header.ConnectionId.String()
			candidates, err := process.ProcessesWithContext(ctx)
			if err != nil {
				return fail(0, err)
			}
			for _, candidate := range candidates {
				envs, err := candidate.Environ()
				if err != nil || len(envs) == 0 {
					continue
				}
				for _, env := range envs {
					if env == expectedEnv {
						pids = append(pids, int(candidate.Pid))
						break
					}
				}
			}
		}
		if len(pids) == 0 {
			return methodKillResponse{ErrNoSuchProcess}
		}
		logger.With("pids", pids).Debug("sending signal to connection processes")

		for _, pid := range pids {
			if err := this.kill(ctx, pid, req.signal); err != nil && !errors.Is(err, ErrNoSuchProcess) {
				return fail(pid, err)
			}
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
