//go:build unix

package user

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
)

// This models XNU's kernel-side EUID selection and gopsutil's Darwin-only UID
// layout. It deliberately does not use Linux UidsWithContext (whose first UID
// is the real UID), invoke native Darwin APIs, or send any OS signals.
type darwinProcessPolicyEntry struct {
	identity        darwinProcessIdentity
	realUID         uint32
	effectiveUID    uint32
	savedUID        uint32
	uids            []uint32
	currentIdentity darwinProcessIdentity
	finalUID        uint32
	referenceErr    error
	inspectionErr   error
	identityErr     error
	killErr         error
}

func darwinPolicyEntry(pid int32, realUID, effectiveUID, savedUID uint32) *darwinProcessPolicyEntry {
	identity := darwinProcessIdentity{pid: pid, startSeconds: 1700000000, startMicros: 123456}
	return &darwinProcessPolicyEntry{
		identity: identity, currentIdentity: identity,
		realUID: realUID, effectiveUID: effectiveUID, savedUID: savedUID,
		uids: []uint32{effectiveUID}, finalUID: effectiveUID,
	}
}

type darwinProcessPolicyModel struct {
	t          *testing.T
	entries    []*darwinProcessPolicyEntry
	queryErr   error
	queries    []Id
	referenced []int32
	inspected  []int32
	identities []int32
	verified   []int32
	killed     []int32
}

func (m *darwinProcessPolicyModel) query(name string, args ...int) ([]darwinProcessIdentity, error) {
	m.t.Helper()
	// Literal expectations also catch accidentally switching the production
	// selector to ruid or all; do not compare the constant against itself.
	require.Equal(m.t, "kern.proc.uid", name)
	require.Len(m.t, args, 1)
	m.queries = append(m.queries, Id(args[0]))
	var result []darwinProcessIdentity
	for _, entry := range m.entries {
		if entry.effectiveUID == uint32(args[0]) {
			result = append(result, entry.identity)
		}
	}
	return result, m.queryErr
}

func (m *darwinProcessPolicyModel) entry(pid int32) *darwinProcessPolicyEntry {
	m.t.Helper()
	for _, entry := range m.entries {
		if entry.identity.pid == pid {
			return entry
		}
	}
	m.t.Fatalf("unexpected process %d outside kernel-filtered list", pid)
	return nil
}

func (m *darwinProcessPolicyModel) reference(ctx context.Context, pid int32) (*process.Process, error) {
	m.referenced = append(m.referenced, pid)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &process.Process{Pid: pid}, m.entry(pid).referenceErr
}

func (m *darwinProcessPolicyModel) list(ctx context.Context, id Id) ([]darwinProcessCandidate, error) {
	return darwinProcessesByUID(ctx, id, m.query, m.reference)
}

func (m *darwinProcessPolicyModel) checks() darwinProcessChecks {
	return darwinProcessChecks{
		uids: func(ctx context.Context, p *process.Process) ([]uint32, error) {
			m.inspected = append(m.inspected, p.Pid)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entry := m.entry(p.Pid)
			return entry.uids, entry.inspectionErr
		},
		identity: func(ctx context.Context, p *process.Process) (darwinProcessIdentity, error) {
			m.identities = append(m.identities, p.Pid)
			if err := ctx.Err(); err != nil {
				return darwinProcessIdentity{}, err
			}
			entry := m.entry(p.Pid)
			return entry.currentIdentity, entry.identityErr
		},
		kill: func(ctx context.Context, p *process.Process, uid uint32) error {
			m.verified = append(m.verified, p.Pid)
			if err := ctx.Err(); err != nil {
				return err
			}
			entry := m.entry(p.Pid)
			// Model the unchanged killVerifiedUserProcess boundary: it must
			// still be invoked and must recheck the owner before signaling.
			if entry.finalUID != uid {
				return fmt.Errorf("process %d changed UID during cleanup", p.Pid)
			}
			if entry.killErr != nil {
				return entry.killErr
			}
			m.killed = append(m.killed, p.Pid)
			return nil
		},
	}
}

func TestDarwinProcessPolicyKernelEUIDSelection(t *testing.T) {
	m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{
		darwinPolicyEntry(11, 501, 501, 501),
		darwinPolicyEntry(12, 600, 501, 700), // matching EUID, different real/saved UID
		darwinPolicyEntry(13, 501, 600, 700), // matching real UID is insufficient
		darwinPolicyEntry(14, 600, 700, 501), // matching saved UID is insufficient
		darwinPolicyEntry(15, 600, 600, 600),
	}}
	for _, entry := range m.entries[2:] {
		// Even an uninspectable foreign process must not be constructed or
		// read: the kernel UID query excludes it before userspace inspection.
		entry.referenceErr = syscall.EPERM
		entry.inspectionErr = syscall.EIO
	}

	err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

	require.NoError(t, err)
	require.Equal(t, []Id{501}, m.queries)
	for _, actual := range [][]int32{m.referenced, m.inspected, m.identities, m.verified, m.killed} {
		require.Equal(t, []int32{11, 12}, actual)
	}
}

func TestDarwinProcessPolicyEnumerationErrorsFailClosed(t *testing.T) {
	for _, cause := range []error{syscall.EIO, syscall.EPERM, syscall.ENOMEM, os.ErrNotExist} {
		t.Run(cause.Error(), func(t *testing.T) {
			m := &darwinProcessPolicyModel{t: t, queryErr: cause, entries: []*darwinProcessPolicyEntry{darwinPolicyEntry(11, 501, 501, 501)}}

			err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

			require.ErrorIs(t, err, cause)
			require.ErrorContains(t, err, "cannot list processes of Darwin user 501")
			require.Equal(t, []Id{501}, m.queries, "no retry or fallback to all processes")
			require.Empty(t, m.referenced, "partial enumeration results must not be used")
			require.Empty(t, m.inspected)
			require.Empty(t, m.verified)
			require.Empty(t, m.killed)
		})
	}
}

func TestDarwinProcessPolicyTargetErrorsFailClosed(t *testing.T) {
	for _, stage := range []string{"reference", "UID", "identity", "kill"} {
		for _, cause := range []error{syscall.EIO, syscall.EPERM} {
			t.Run(stage+"/"+cause.Error(), func(t *testing.T) {
				entry := darwinPolicyEntry(11, 501, 501, 501)
				switch stage {
				case "reference":
					entry.referenceErr = cause
				case "UID":
					entry.inspectionErr = cause
				case "identity":
					entry.identityErr = cause
				case "kill":
					entry.killErr = cause
				}
				m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry, darwinPolicyEntry(12, 501, 501, 501)}}

				err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

				require.ErrorIs(t, err, cause)
				require.Empty(t, m.killed)
				require.NotContains(t, m.verified, int32(12), "stop on the first failure")
				if stage == "reference" || stage == "UID" || stage == "identity" {
					require.Empty(t, m.verified)
				}
			})
		}
	}
}

func TestDarwinProcessPolicyOnlyKnownAbsenceIsSkipped(t *testing.T) {
	for _, stage := range []string{"reference", "UID", "identity", "kill", "reference not running"} {
		t.Run(stage, func(t *testing.T) {
			entry := darwinPolicyEntry(11, 501, 501, 501)
			missing := &os.PathError{Op: "inspect", Path: "process", Err: os.ErrNotExist}
			switch stage {
			case "reference":
				entry.referenceErr = missing
			case "UID":
				entry.inspectionErr = missing
			case "identity":
				entry.identityErr = missing
			case "kill":
				entry.killErr = missing
			case "reference not running":
				entry.referenceErr = process.ErrorProcessNotRunning
			}
			m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry, darwinPolicyEntry(12, 501, 501, 501)}}

			require.NoError(t, killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks()))
			require.Equal(t, []int32{12}, m.killed)
		})
	}
}

func TestDarwinProcessPolicyRechecksOwner(t *testing.T) {
	for _, currentUIDs := range [][]uint32{nil, {}, {600}, {600, 501}} {
		t.Run(fmt.Sprint(currentUIDs), func(t *testing.T) {
			entry := darwinPolicyEntry(11, 501, 501, 501)
			entry.uids = currentUIDs // owner changed after kernel enumeration
			m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry}}

			require.NoError(t, killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks()))
			require.Equal(t, []int32{11}, m.inspected)
			require.Empty(t, m.identities)
			require.Empty(t, m.verified)
			require.Empty(t, m.killed)
		})
	}
}

func TestDarwinProcessPolicyKeepsFinalOwnerCheck(t *testing.T) {
	entry := darwinPolicyEntry(11, 600, 501, 700)
	entry.finalUID = 600 // owner changes after inspection, at the existing killer
	m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry}}

	err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

	require.ErrorContains(t, err, "changed UID during cleanup")
	require.Equal(t, []int32{11}, m.identities)
	require.Equal(t, []int32{11}, m.verified)
	require.Empty(t, m.killed)
}

func TestDarwinProcessPolicyRejectsPIDReuse(t *testing.T) {
	for _, field := range []string{"PID", "seconds", "microseconds"} {
		t.Run(field, func(t *testing.T) {
			entry := darwinPolicyEntry(11, 600, 501, 700)
			switch field {
			case "PID":
				entry.currentIdentity.pid++
			case "seconds":
				entry.currentIdentity.startSeconds++
			case "microseconds":
				entry.currentIdentity.startMicros++ // same millisecond must not compare equal
			}
			m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry}}

			err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

			require.ErrorContains(t, err, "changed identity during cleanup")
			require.Equal(t, []int32{11}, m.inspected)
			require.Equal(t, []int32{11}, m.identities)
			require.Empty(t, m.verified)
			require.Empty(t, m.killed)
		})
	}
}

func TestDarwinProcessPolicyEmptyEnumerationAndSelf(t *testing.T) {
	for _, selfOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(selfOnly), func(t *testing.T) {
			m := &darwinProcessPolicyModel{t: t}
			if selfOnly {
				entry := darwinPolicyEntry(99, 501, 501, 501)
				entry.inspectionErr = syscall.EIO
				m.entries = []*darwinProcessPolicyEntry{entry}
			}

			require.NoError(t, killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks()))
			require.Equal(t, []Id{501}, m.queries)
			require.Empty(t, m.inspected)
			require.Empty(t, m.identities)
			require.Empty(t, m.verified)
			require.Empty(t, m.killed)
		})
	}
}

func TestDarwinProcessPolicyCancellation(t *testing.T) {
	for _, stage := range []string{"before enumeration", "query", "reference", "after list", "UID", "identity", "between processes"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{darwinPolicyEntry(11, 501, 501, 501), darwinPolicyEntry(12, 501, 501, 501)}}
			checks := m.checks()
			list := m.list
			switch stage {
			case "before enumeration":
				cancel()
			case "query":
				list = func(ctx context.Context, id Id) ([]darwinProcessCandidate, error) {
					return darwinProcessesByUID(ctx, id, func(name string, args ...int) ([]darwinProcessIdentity, error) {
						result, err := m.query(name, args...)
						cancel()
						return result, err
					}, m.reference)
				}
			case "reference":
				list = func(ctx context.Context, id Id) ([]darwinProcessCandidate, error) {
					return darwinProcessesByUID(ctx, id, m.query, func(ctx context.Context, pid int32) (*process.Process, error) {
						p, err := m.reference(ctx, pid)
						cancel()
						return p, err
					})
				}
			case "after list":
				list = func(ctx context.Context, id Id) ([]darwinProcessCandidate, error) {
					result, err := m.list(ctx, id)
					cancel()
					return result, err
				}
			case "UID":
				inspect := checks.uids
				checks.uids = func(ctx context.Context, p *process.Process) ([]uint32, error) {
					result, err := inspect(ctx, p)
					cancel()
					return result, err
				}
			case "identity":
				inspect := checks.identity
				checks.identity = func(ctx context.Context, p *process.Process) (darwinProcessIdentity, error) {
					result, err := inspect(ctx, p)
					cancel()
					return result, err
				}
			case "between processes":
				kill := checks.kill
				checks.kill = func(ctx context.Context, p *process.Process, uid uint32) error {
					err := kill(ctx, p, uid)
					cancel()
					return err
				}
			}

			err := killDarwinProcessesByUID(ctx, 501, 99, list, checks)

			require.ErrorIs(t, err, context.Canceled)
			if stage == "between processes" {
				require.Equal(t, []int32{11}, m.killed)
			} else {
				require.Empty(t, m.killed)
				require.Empty(t, m.verified)
			}
			if stage == "before enumeration" {
				require.Empty(t, m.queries)
			}
		})
	}
}

func TestDarwinProcessPolicyRejectsInvalidReferences(t *testing.T) {
	for _, pid := range []int32{0, -1, 11} {
		t.Run(fmt.Sprint(pid), func(t *testing.T) {
			query := func(string, ...int) ([]darwinProcessIdentity, error) {
				return []darwinProcessIdentity{{pid: pid}}, nil
			}
			called := false
			_, err := darwinProcessesByUID(t.Context(), 501, query, func(context.Context, int32) (*process.Process, error) {
				called = true
				return &process.Process{Pid: 12}, nil
			})
			if pid == 0 {
				require.NoError(t, err)
				require.False(t, called, "kernel_task must never become a signal target")
			} else {
				require.Error(t, err)
			}
		})
	}
	_, err := darwinProcessesByUID(t.Context(), 501, func(string, ...int) ([]darwinProcessIdentity, error) {
		return []darwinProcessIdentity{{pid: 11}}, nil
	}, func(context.Context, int32) (*process.Process, error) { return nil, nil })
	require.ErrorContains(t, err, "invalid Darwin process reference")
}

func TestDarwinProcessPolicyDoesNotTreatESRCHAsGenericAbsence(t *testing.T) {
	entry := darwinPolicyEntry(11, 501, 501, 501)
	entry.inspectionErr = syscall.ESRCH
	m := &darwinProcessPolicyModel{t: t, entries: []*darwinProcessPolicyEntry{entry}}

	err := killDarwinProcessesByUID(t.Context(), 501, 99, m.list, m.checks())

	require.ErrorIs(t, err, syscall.ESRCH)
	require.Empty(t, m.verified)
	require.Empty(t, m.killed)
}
