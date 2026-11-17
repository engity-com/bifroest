//go:build linux

package windowslocal

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestS4USystemContextPinsAndRetiresRealOSThread(t *testing.T) {
	var worker int
	var inspected []int
	err := runS4USystemContext(t.Context(), func() error { inspected = append(inspected, unix.Gettid()); return nil }, func() error {
		worker = unix.Gettid()
		runtime.Gosched()
		if unix.Gettid() != worker {
			return fmt.Errorf("native work changed OS thread")
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, inspected, 4)
	caller := inspected[0]
	require.NotEqual(t, caller, worker)
	require.NotEqual(t, os.Getpid(), worker, "native work must not run on Go's parked-on-exit startup thread")
	require.Equal(t, []int{caller, worker, worker, caller}, inspected, "guard must pin the caller itself, without an outer test pin")
	if !assert.Eventually(t, func() bool { return errors.Is(unix.Tgkill(os.Getpid(), worker, 0), unix.ESRCH) }, 2*time.Second, 10*time.Millisecond, "completed worker must retire its thread, not pool it") {
		state, _ := os.ReadFile("/proc/self/task/" + strconv.Itoa(worker) + "/stat")
		wait, _ := os.ReadFile("/proc/self/task/" + strconv.Itoa(worker) + "/wchan")
		parts := strings.Fields(string(state))
		kernelState := "unavailable"
		if len(parts) >= 3 {
			kernelState = parts[2]
		}
		t.Logf("thread lifecycle diagnostic: caller=%d worker=%d main=%d state=%s wait=%s", caller, worker, os.Getpid(), kernelState, strings.TrimSpace(string(wait)))
	}
}
