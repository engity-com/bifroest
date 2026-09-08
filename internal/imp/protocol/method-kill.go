package protocol

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	ErrNoSuchProcess              = errors.System.Newf("no such process")
	errProcessRegistrationPending = errors.System.Newf("process registration is still pending")
)

const processRegistrationWaitTimeout = time.Second

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

type processTarget struct {
	pid               int
	processGroup      bool
	expectedCreatedAt *int64
	expectedEnv       string
	groupExpectedEnv  string
}

type signaledProcessGroups map[int]struct{}

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
	if pid < 0 || int64(pid) > math.MaxInt32 {
		return methodKillResponse{ErrNoSuchProcess}
	}

	var targets []processTarget
	targetPids := make(map[int]struct{})
	if pid != 0 {
		target := processTarget{pid: pid, processGroup: processGroup}
		if processGroup {
			target.expectedEnv = expectedEnv
			target.groupExpectedEnv = expectedEnv
		}
		targets = append(targets, target)
		targetPids[pid] = struct{}{}
	}
	if pid == 0 {
		pidFn := filepath.Join(stateDirectory, stateId.String()+".pid")
		plainPid, err := waitForRegisteredProcess(ctx, pidFn)
		if errors.Is(err, errProcessRegistrationPending) {
			latest, latestErr := os.ReadFile(pidFn)
			if latestErr == nil {
				plainPid = latest
			} else if !errors.Is(latestErr, os.ErrNotExist) {
				return fail(0, latestErr)
			}
			if latestErr == nil && !isRegisteredStartingProcess(plainPid) {
				err = nil
			} else if latestErr == nil && registeredStartingProcessMatches(plainPid) {
				return methodKillResponse{ErrNoSuchProcess}
			} else {
				_ = os.Remove(pidFn)
				err = os.ErrNotExist
			}
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fail(0, err)
		}
		if err == nil {
			if storedPid, expectedCreatedAt, ok := registeredProcess(plainPid); ok {
				target := processTarget{
					pid:               storedPid,
					processGroup:      processGroup,
					expectedCreatedAt: expectedCreatedAt,
					groupExpectedEnv:  expectedEnv,
				}
				if expectedCreatedAt == nil {
					target.expectedEnv = expectedEnv
				}
				if target.matchesIdentity() {
					targets = append(targets, target)
					targetPids[storedPid] = struct{}{}
				} else {
					_ = os.Remove(pidFn)
				}
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
						createdAt, err := candidate.CreateTime()
						if err != nil {
							break
						}
						targets = append(targets, processTarget{
							pid:               pid,
							processGroup:      processGroup,
							expectedCreatedAt: &createdAt,
							expectedEnv:       expectedEnv,
							groupExpectedEnv:  expectedEnv,
						})
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
	signaledGroups := make(signaledProcessGroups)
	for _, target := range targets {
		if err := this.kill(ctx, target, signal, signaledGroups); err == nil {
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

func waitForRegisteredProcess(ctx context.Context, pidFn string) ([]byte, error) {
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	timeout := time.NewTimer(processRegistrationWaitTimeout)
	defer timeout.Stop()
	for {
		raw, err := os.ReadFile(pidFn)
		if err != nil || !isRegisteredStartingProcess(raw) {
			return raw, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout.C:
			return raw, errProcessRegistrationPending
		case <-poll.C:
		}
	}
}

func isRegisteredStartingProcess(raw []byte) bool {
	fields := strings.Fields(string(raw))
	return len(fields) == 3 && fields[0] == execution.StateStartingMarker
}

func registeredStartingProcessMatches(raw []byte) bool {
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != execution.StateStartingMarker {
		return false
	}
	pid, expectedCreatedAt, ok := registeredProcess([]byte(strings.Join(fields[1:], " ")))
	return ok && (processTarget{pid: pid, expectedCreatedAt: expectedCreatedAt}).matchesIdentity()
}

func registeredProcess(raw []byte) (int, *int64, bool) {
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || len(fields) > 2 {
		return 0, nil, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return 0, nil, false
	}
	if len(fields) == 1 {
		return pid, nil, true
	}
	expectedCreatedAt, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, nil, false
	}
	return pid, &expectedCreatedAt, true
}

func registeredProcessMatches(raw []byte, expectedEnv string) bool {
	pid, expectedCreatedAt, ok := registeredProcess(raw)
	target := processTarget{
		pid:               pid,
		expectedCreatedAt: expectedCreatedAt,
	}
	if expectedCreatedAt == nil {
		target.expectedEnv = expectedEnv
	}
	return ok && target.matchesIdentity()
}

func (this processTarget) matchesIdentity() bool {
	if this.expectedCreatedAt != nil {
		candidate, err := process.NewProcess(int32(this.pid))
		if err != nil {
			return false
		}
		createdAt, err := candidate.CreateTime()
		if err != nil || createdAt != *this.expectedCreatedAt {
			return false
		}
	}
	return this.expectedEnv == "" || processHasEnvironment(this.pid, this.expectedEnv)
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
