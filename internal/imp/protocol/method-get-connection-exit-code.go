package protocol

import (
	"bytes"
	"context"
	goos "os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/engity-com/bifroest/pkg/codec"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
)

const (
	executionResultRetention       = 24 * time.Hour
	executionResultCleanupInterval = time.Minute
	executionResultMaxRetained     = 1024
	executionResultAckTimeout      = 5 * time.Second
)

type methodGetExecutionExitCodeRequest struct {
	executionId execution.Id
}

func (this methodGetExecutionExitCodeRequest) EncodeMsgpack(enc *msgpack.Encoder) error {
	return this.EncodeMsgPack(enc)
}

func (this *methodGetExecutionExitCodeRequest) DecodeMsgpack(dec *msgpack.Decoder) (err error) {
	return this.DecodeMsgPack(dec)
}

func (this methodGetExecutionExitCodeRequest) EncodeMsgPack(enc codec.MsgPackEncoder) error {
	return this.executionId.EncodeMsgPack(enc)
}

func (this *methodGetExecutionExitCodeRequest) DecodeMsgPack(dec codec.MsgPackDecoder) (err error) {
	return this.executionId.DecodeMsgPack(dec)
}

type methodGetConnectionExitCodeRequest struct{}

func (methodGetConnectionExitCodeRequest) EncodeMsgPack(codec.MsgPackEncoder) error  { return nil }
func (*methodGetConnectionExitCodeRequest) DecodeMsgPack(codec.MsgPackDecoder) error { return nil }

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
	return handleFromServerSide(ctx, header, conn, func(*methodGetConnectionExitCodeRequest) methodGetConnectionExitCodeResponse {
		return getExitCode(this.ExitCodeByConnectionIdPath, header.ConnectionId)
	})
}

func (this *imp) handleMethodGetExecutionExitCode(ctx context.Context, header *Header, logger log.Logger, conn codec.MsgPackConn) error {
	fail := func(err error) error {
		return errors.Network.Newf("handling %v failed: %w", header.Method, err)
	}
	var executionId execution.Id
	inFlight := false
	var response methodGetConnectionExitCodeResponse
	err := handleFromServerSide(ctx, header, conn, func(req *methodGetExecutionExitCodeRequest) methodGetConnectionExitCodeResponse {
		executionId = req.executionId
		this.beginExecutionResultDelivery(executionId)
		inFlight = true
		response = this.getExecutionExitCode(executionId)
		return response
	})
	if inFlight {
		defer this.endExecutionResultDelivery(executionId)
	}
	if err != nil || !response.found || response.error != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(executionResultAckTimeout)); err != nil {
		return fail(err)
	}
	acknowledged, err := conn.DecodeBool()
	if err != nil {
		return fail(err)
	}
	if acknowledged {
		path := filepath.Join(this.ExitCodeByConnectionIdPath, execution.StateDirectoryName, executionId.String())
		if removeErr := this.removeAcknowledgedExecutionResult(executionId, path); removeErr != nil && !goos.IsNotExist(removeErr) {
			logger.WithError(removeErr).With("path", path).Warn("cannot remove delivered execution result")
		}
	}
	return nil
}

func (this *imp) removeAcknowledgedExecutionResult(executionId execution.Id, path string) error {
	this.executionResultCleanupMutex.Lock()
	defer this.executionResultCleanupMutex.Unlock()
	if this.executionResultsInFlight[executionId] > 1 {
		return nil
	}
	return goos.Remove(path)
}

func (this *imp) beginExecutionResultDelivery(executionId execution.Id) {
	this.executionResultCleanupMutex.Lock()
	defer this.executionResultCleanupMutex.Unlock()
	if this.executionResultsInFlight == nil {
		this.executionResultsInFlight = make(map[connection.Id]int)
	}
	this.executionResultsInFlight[executionId]++
}

func (this *imp) endExecutionResultDelivery(executionId execution.Id) {
	this.executionResultCleanupMutex.Lock()
	defer this.executionResultCleanupMutex.Unlock()
	if count := this.executionResultsInFlight[executionId]; count > 1 {
		this.executionResultsInFlight[executionId] = count - 1
	} else {
		delete(this.executionResultsInFlight, executionId)
	}
}

func (this *imp) getExecutionExitCode(executionId execution.Id) methodGetConnectionExitCodeResponse {
	directory := filepath.Join(this.ExitCodeByConnectionIdPath, execution.StateDirectoryName)
	this.cleanupStaleExecutionResults(directory, executionId, time.Now())
	return getExitCode(directory, executionId)
}

func getExitCode(directory string, stateId connection.Id) methodGetConnectionExitCodeResponse {
	rsp := methodGetConnectionExitCodeResponse{}
	if !stateId.IsZero() {
		exitCode, err := readExecutionExitCode(directory, stateId)
		if errors.Is(err, connection.ErrNotFound) {
			rsp.found = false
		} else if err != nil {
			rsp.error = err
		} else {
			rsp.found = true
			rsp.exitCode = exitCode
		}
	}
	return rsp
}

func readExecutionExitCode(directory string, executionId connection.Id) (int, error) {
	fn := filepath.Join(directory, executionId.String())
	b, err := goos.ReadFile(fn)
	if goos.IsNotExist(err) {
		return 0, connection.ErrNotFound
	} else if err != nil {
		return 0, err
	}
	exitCode, err := strconv.Atoi(string(bytes.TrimSpace(b)))
	if err != nil {
		_ = goos.Remove(fn)
		return 0, errors.System.Newf("invalid exit code for execution %v: %w", executionId, err)
	}
	return exitCode, nil
}

func (this *imp) cleanupStaleExecutionResults(directory string, except connection.Id, now time.Time) {
	this.executionResultCleanupMutex.Lock()
	if now.Before(this.nextExecutionResultCleanup) {
		this.executionResultCleanupMutex.Unlock()
		return
	}
	this.nextExecutionResultCleanup = now.Add(executionResultCleanupInterval)
	this.executionResultCleanupMutex.Unlock()
	cleanupExecutionResultsExcept(directory, map[connection.Id]struct{}{except: {}}, now, executionResultMaxRetained, this.removeStaleExecutionResult)
}

func (this *imp) removeStaleExecutionResult(executionId connection.Id, path string) {
	this.executionResultCleanupMutex.Lock()
	defer this.executionResultCleanupMutex.Unlock()
	if this.executionResultsInFlight[executionId] == 0 {
		_ = goos.Remove(path)
	}
}

func (this *imp) periodicallyCleanupExecutionResults(ctx context.Context) {
	directory := filepath.Join(this.ExitCodeByConnectionIdPath, execution.StateDirectoryName)
	this.cleanupStaleExecutionResults(directory, connection.Id{}, time.Now())
	ticker := time.NewTicker(executionResultCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			this.cleanupStaleExecutionResults(directory, connection.Id{}, now)
		}
	}
}

func cleanupStaleExecutionResults(directory string, except connection.Id, now time.Time) {
	cleanupExecutionResults(directory, except, now, executionResultMaxRetained)
}

func cleanupExecutionResults(directory string, except connection.Id, now time.Time, maxRetained int) {
	cleanupExecutionResultsExcept(directory, map[connection.Id]struct{}{except: {}}, now, maxRetained, func(_ connection.Id, path string) {
		_ = goos.Remove(path)
	})
}

func cleanupExecutionResultsExcept(directory string, exceptions map[connection.Id]struct{}, now time.Time, maxRetained int, remove func(connection.Id, string)) {
	entries, err := goos.ReadDir(directory)
	if err != nil {
		return
	}
	type retainedResult struct {
		executionId connection.Id
		path        string
		modTime     time.Time
	}
	var retained []retainedResult
	for _, entry := range entries {
		name := entry.Name()
		isPid := strings.HasSuffix(name, ".pid")
		if isPid {
			name = strings.TrimSuffix(name, ".pid")
		}
		var executionId connection.Id
		if entry.IsDir() || executionId.Set(name) != nil {
			continue
		}
		if _, except := exceptions[executionId]; except {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if now.Sub(info.ModTime()) < executionResultRetention {
			if !isPid {
				retained = append(retained, retainedResult{executionId: executionId, path: path, modTime: info.ModTime()})
			}
			continue
		}
		if isPid {
			raw, err := goos.ReadFile(path)
			if err == nil {
				activeExecution := false
				if _, activeExecution = registeredProcess(raw, execution.EnvName+"="+executionId.String()); !activeExecution {
					_, activeExecution = registeredProcess(raw, connection.EnvName+"="+executionId.String())
				}
				if activeExecution {
					continue
				}
			}
		}
		remove(executionId, path)
	}
	if maxRetained >= 0 && len(retained) > maxRetained {
		sort.Slice(retained, func(i, j int) bool { return retained[i].modTime.Before(retained[j].modTime) })
		for _, result := range retained[:len(retained)-maxRetained] {
			remove(result.executionId, result.path)
		}
	}
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

func (this *Master) methodGetExecutionExitCode(ctx context.Context, ref Ref, connectionId connection.Id, executionId execution.Id) (result int, _ error) {
	if err := this.do(ctx, ref, connectionId, MethodGetExecutionExitCode, func(header *Header, conn codec.MsgPackConn) error {
		return handleFromClientSide(ctx, header, conn, methodGetExecutionExitCodeRequest{executionId: executionId}, func(v *methodGetConnectionExitCodeResponse) error {
			if err := v.error; err != nil {
				return errors.AsRemoteError(err)
			}
			if !v.found {
				return connection.ErrNotFound
			}
			result = v.exitCode
			// The result was received successfully. Some proxied transports can
			// report a concurrent remote close while the ACK was already delivered.
			_ = conn.EncodeBool(true)
			return nil
		})
	}); err != nil {
		return 0, err
	}

	return result, nil
}
