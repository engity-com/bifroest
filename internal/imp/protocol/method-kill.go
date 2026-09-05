package protocol

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/echocat/slf4g"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	ErrNoSuchProcess = errors.System.Newf("no such process")
)

type methodKillExecutionRequest struct {
	executionId execution.Id
	pid         int
	signal      sys.Signal
}

func (this methodKillExecutionRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodKillExecutionRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodKillExecutionRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := this.executionId.EncodeMsgPack(enc); err != nil {
		return err
	}
	if err := enc.EncodeInt(int64(this.pid)); err != nil {
		return err
	}
	if err := this.signal.EncodeMsgPack(enc); err != nil {
		return err
	}
	return nil
}

func (this *methodKillExecutionRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if err = this.executionId.DecodeMsgPack(dec); err != nil {
		return err
	}
	if this.pid, err = dec.DecodeInt(); err != nil {
		return err
	}
	if err = this.signal.DecodeMsgPack(dec); err != nil {
		return err
	}
	return nil
}

type methodKillRequest struct {
	pid    int
	signal sys.Signal
}

func (this methodKillRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	if err := enc.EncodeInt(int64(this.pid)); err != nil {
		return err
	}
	return this.signal.EncodeMsgPack(enc)
}

func (this *methodKillRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	if this.pid, err = dec.DecodeInt(); err != nil {
		return err
	}
	return this.signal.DecodeMsgPack(dec)
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
		return this.killProcesses(ctx, header, logger, this.ExitCodeByConnectionIdPath, header.ConnectionId, connection.EnvName+"="+header.ConnectionId.String(), req.pid, req.signal, req.pid == 0)
	})
}

func (this *imp) handleMethodKillExecution(ctx context.Context, header *Header, logger log.Logger, conn codec.MsgPackConn) error {
	return handleFromServerSide(ctx, header, conn, func(req *methodKillExecutionRequest) methodKillResponse {
		stateDirectory := filepath.Join(this.ExitCodeByConnectionIdPath, execution.StateDirectoryName)
		return this.killProcesses(ctx, header, logger.With("execution", req.executionId), stateDirectory, req.executionId, execution.EnvName+"="+req.executionId.String(), req.pid, req.signal, true)
	})
}

func (this *imp) killProcesses(ctx context.Context, header *Header, logger log.Logger, stateDirectory string, stateId connection.Id, expectedEnv string, pid int, signal sys.Signal, processGroup bool) methodKillResponse {
	fail := func(pid int, err error) methodKillResponse {
		return methodKillResponse{errors.System.Newf("cannot kill process %d of %v with %v: %w", pid, header.ConnectionId, signal, err)}
	}

	type target struct {
		pid          int
		processGroup bool
	}
	targets := []target{{pid: pid}}
	targetPids := map[int]struct{}{pid: {}}
	if pid != 0 && processGroup && !processHasEnvironment(pid, expectedEnv) {
		return methodKillResponse{ErrNoSuchProcess}
	}
	if pid == 0 {
		targets = nil
		pidFn := filepath.Join(stateDirectory, stateId.String()+".pid")
		if plainPid, err := os.ReadFile(pidFn); err == nil {
			if storedPid, ok := registeredProcess(plainPid, expectedEnv); ok {
				targets = append(targets, target{pid: storedPid, processGroup: processGroup})
				targetPids[storedPid] = struct{}{}
			} else {
				_ = os.Remove(pidFn)
			}
		}
	}
	if len(targets) == 0 || processGroup {
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
					pid := int(candidate.Pid)
					if _, exists := targetPids[pid]; !exists {
						targets = append(targets, target{pid: pid, processGroup: processGroup})
						targetPids[pid] = struct{}{}
					}
					break
				}
			}
		}
	}
	if len(targets) == 0 {
		return methodKillResponse{ErrNoSuchProcess}
	}
	logger.With("targets", targets).Debug("sending signal to execution processes")

	signaled := false
	for _, target := range targets {
		if err := this.kill(ctx, target.pid, signal, target.processGroup); err == nil {
			signaled = true
		} else if !errors.Is(err, ErrNoSuchProcess) {
			return fail(target.pid, err)
		}
	}
	if !signaled {
		return methodKillResponse{ErrNoSuchProcess}
	}

	return methodKillResponse{}
}

func registeredProcess(raw []byte, legacyExpectedEnv string) (int, bool) {
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return 0, false
	}
	if len(fields) == 1 {
		return pid, processHasEnvironment(pid, legacyExpectedEnv)
	}
	expectedCreatedAt, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	candidate, err := process.NewProcess(int32(pid))
	if err != nil {
		return 0, false
	}
	createdAt, err := candidate.CreateTime()
	return pid, err == nil && createdAt == expectedCreatedAt
}

func processHasEnvironment(pid int, expected string) bool {
	candidate, err := process.NewProcess(int32(pid))
	if err != nil {
		return false
	}
	envs, err := candidate.Environ()
	if err != nil {
		return false
	}
	for _, env := range envs {
		if env == expected {
			return true
		}
	}
	return false
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

func (this *Master) methodKillExecution(ctx context.Context, ref Ref, connectionId connection.Id, executionId execution.Id, pid int, signal sys.Signal) error {
	return this.do(ctx, ref, connectionId, MethodKillExecution, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodKillExecutionRequest{
			executionId: executionId,
			pid:         pid,
			signal:      signal,
		}, func(v *methodKillResponse) error {
			return errors.AsRemoteError(v.error)
		})
	})
}
