//go:build darwin

package user

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/sys/unix"
)

func listDarwinProcessesByUID(ctx context.Context, id Id) ([]darwinProcessCandidate, error) {
	return darwinProcessesByUID(ctx, id, queryDarwinProcessIdentities, process.NewProcessWithContext)
}

func queryDarwinProcessIdentities(name string, args ...int) ([]darwinProcessIdentity, error) {
	// XNU bsd/kern/kern_sysctl.c registers kern.proc.uid as KERN_PROC_UID;
	// sysdoproc_filt_KERN_PROC_UID compares kauth_cred_getuid (effective UID).
	// kern.proc.ruid would change which processes this repository cleans up.
	entries, err := unix.SysctlKinfoProcSlice(name, args...)
	if err != nil {
		return nil, err
	}
	result := make([]darwinProcessIdentity, 0, len(entries))
	for i := range entries {
		result = append(result, darwinProcessIdentityFromKinfo(&entries[i]))
	}
	return result, nil
}

func darwinProcessUIDs(ctx context.Context, p *process.Process) ([]uint32, error) {
	return p.UidsWithContext(ctx)
}

func inspectDarwinProcessIdentity(ctx context.Context, p *process.Process) (darwinProcessIdentity, error) {
	if err := ctx.Err(); err != nil {
		return darwinProcessIdentity{}, err
	}
	entry, err := unix.SysctlKinfoProc("kern.proc.pid", int(p.Pid))
	if err != nil {
		return darwinProcessIdentity{}, err
	}
	return darwinProcessIdentityFromKinfo(entry), ctx.Err()
}

func darwinProcessIdentityFromKinfo(entry *unix.KinfoProc) darwinProcessIdentity {
	return darwinProcessIdentity{
		pid:          entry.Proc.P_pid,
		startSeconds: entry.Proc.P_starttime.Sec,
		startMicros:  int64(entry.Proc.P_starttime.Usec),
	}
}
