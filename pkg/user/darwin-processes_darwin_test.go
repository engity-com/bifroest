//go:build darwin

package user

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestDarwinProcessIdentityPreservesKernelStartTime(t *testing.T) {
	var entry unix.KinfoProc
	entry.Proc.P_pid = 11
	entry.Proc.P_starttime.Sec = 1700000000
	entry.Proc.P_starttime.Usec = 123456

	original := darwinProcessIdentityFromKinfo(&entry)
	require.Equal(t, darwinProcessIdentity{pid: 11, startSeconds: 1700000000, startMicros: 123456}, original)

	// Do not lose precision to gopsutil's millisecond CreateTime representation:
	// two process identities within the same millisecond must remain distinct.
	entry.Proc.P_starttime.Usec++
	require.NotEqual(t, original, darwinProcessIdentityFromKinfo(&entry))
}
