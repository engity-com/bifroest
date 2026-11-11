//go:build unix

package user

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/shirou/gopsutil/v4/process"

	berrors "github.com/engity-com/bifroest/pkg/errors"
)

// gopsutil v4.26.9 returns only Eproc.Ucred.Uid from Darwin UidsWithContext.
// XNU's kern.proc.uid filters by that same effective UID, not the real/saved UID.
const darwinProcessUIDSysctl = "kern.proc.uid"

type darwinProcessIdentity struct {
	pid          int32
	startSeconds int64
	startMicros  int64
}

type darwinProcessCandidate struct {
	process  *process.Process
	identity darwinProcessIdentity
}

type darwinProcessLister func(context.Context, Id) ([]darwinProcessCandidate, error)
type darwinProcessQuery func(string, ...int) ([]darwinProcessIdentity, error)

type darwinProcessChecks struct {
	uids     func(context.Context, *process.Process) ([]uint32, error)
	identity func(context.Context, *process.Process) (darwinProcessIdentity, error)
	kill     func(context.Context, *process.Process, uint32) error
}

// The query must filter in the kernel; never fall back to kern.proc.all. Keeping
// this small policy portable lets injected tests exercise the production path
// without pretending to execute Darwin sysctls or send signals on another OS.
func darwinProcessesByUID(ctx context.Context, id Id, query darwinProcessQuery, newProcess func(context.Context, int32) (*process.Process, error)) ([]darwinProcessCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshots, err := query(darwinProcessUIDSysctl, int(id))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]darwinProcessCandidate, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// PID 0 (kernel_task) cannot be a signal target. gopsutil's previous
		// all-process enumeration also excluded it via NewProcessWithContext.
		if snapshot.pid == 0 {
			continue
		}
		if snapshot.pid < 0 {
			return nil, fmt.Errorf("invalid Darwin process PID %d", snapshot.pid)
		}
		candidate, err := newProcess(ctx, snapshot.pid)
		if os.IsNotExist(err) || errors.Is(err, process.ErrorProcessNotRunning) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cannot reference process %d: %w", snapshot.pid, err)
		}
		if candidate == nil || candidate.Pid != snapshot.pid {
			return nil, fmt.Errorf("invalid Darwin process reference for PID %d", snapshot.pid)
		}
		result = append(result, darwinProcessCandidate{process: candidate, identity: snapshot})
	}
	return result, ctx.Err()
}

func killDarwinProcessesByUID(ctx context.Context, id Id, self int32, list darwinProcessLister, checks darwinProcessChecks) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	candidates, err := list(ctx, id)
	if err != nil {
		return berrors.Newf(berrors.System, "cannot list processes of Darwin user %d: %w", id, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := candidate.process
		if p.Pid == self {
			continue
		}
		uids, err := checks.uids(ctx, p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return berrors.Newf(berrors.System, "cannot inspect process %d: %w", p.Pid, err)
		}
		if len(uids) == 0 || uids[0] != uint32(id) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := checks.identity(ctx, p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return berrors.Newf(berrors.System, "cannot inspect identity of process %d: %w", p.Pid, err)
		}
		if current != candidate.identity {
			return fmt.Errorf("process %d changed identity during cleanup", p.Pid)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Keep the existing final UID recheck and signal implementation. The
		// snapshot/start-time check is an additional guard, not a replacement.
		if err := checks.kill(ctx, p, uint32(id)); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return berrors.Newf(berrors.System, "cannot kill process %d of Darwin user %d: %w", p.Pid, id, err)
		}
	}
	return ctx.Err()
}
