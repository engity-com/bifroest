//go:build windows

package environment

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

const localConPTYClientProgressEnv = "BIFROEST_CONPTY_TEST_CLIENT_PROGRESS_PREFIX"

var localConPTYClientProgressPhases = [...]string{
	"client.entered",
	"client.stdin.begin", "client.stdin.returned",
	"client.stdout.begin", "client.stdout.returned",
	"client.stderr.begin", "client.stderr.returned",
	"client.identity.begin", "client.identity.returned",
	"client.geometry.begin", "client.geometry.returned",
	"client.output.begin", "client.output.returned",
	"client.diagnostic.begin", "client.diagnostic.returned",
	"client.handshake.begin", "client.handshake.returned",
	"client.exit",
}

// Test-only, out-of-band observations: neither console I/O nor filesystem
// writes carry these markers. Production binaries contain none of this code.
// An absent marker is unobserved, not proof that native initialization stopped.
type localConPTYClientProgress struct {
	prefix string
	events []windows.Handle
}

func newLocalConPTYClientProgress(t *testing.T) *localConPTYClientProgress {
	t.Helper()
	if os.Getenv("BIFROEST_TEST_CONPTY_CLIENT_PROGRESS") != "1" {
		return nil
	}
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	require.NoError(t, err)
	result := &localConPTYClientProgress{prefix: fmt.Sprintf(`Local\bifroest-conpty-test-%x-`, nonce)}
	t.Cleanup(func() {
		for _, event := range result.events {
			require.NoError(t, windows.CloseHandle(event))
		}
	})
	for _, phase := range localConPTYClientProgressPhases {
		name, err := windows.UTF16PtrFromString(result.prefix + phase)
		require.NoError(t, err)
		event, err := windows.CreateEvent(nil, 1, 0, name)
		require.NoError(t, err)
		result.events = append(result.events, event)
	}
	return result
}

func localConPTYClientPhaseObserver(prefix string) func(string) {
	return func(phase string) {
		if prefix == "" {
			return
		}
		known := false
		for _, candidate := range localConPTYClientProgressPhases {
			if phase == candidate {
				known = true
				break
			}
		}
		if !known {
			return
		}
		name, err := windows.UTF16PtrFromString(prefix + phase)
		if err != nil {
			return
		}
		event, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
		if err != nil {
			return
		}
		_ = windows.SetEvent(event)
		_ = windows.CloseHandle(event)
	}
}

func (progress *localConPTYClientProgress) snapshot() string {
	if progress == nil {
		return "disabled"
	}
	var observed []string
	for index, event := range progress.events {
		status, err := windows.WaitForSingleObject(event, 0)
		if err != nil || status != windows.WAIT_OBJECT_0 && status != uint32(windows.WAIT_TIMEOUT) {
			return "unknown-event-query"
		}
		if status == windows.WAIT_OBJECT_0 {
			observed = append(observed, localConPTYClientProgressPhases[index])
		}
	}
	if len(observed) == 0 {
		return "unobserved"
	}
	return strings.Join(observed, ",")
}

// One zero-wait, bounded observation before killing a timed-out relay. Do not
// suspend processes, enumerate their command lines or read their environment.
func localConPTYTestProcessSnapshot(relayPID uint32) string {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "unknown-process-snapshot"
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	var processes []windows.ProcessEntry32
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if len(processes) == 4096 {
			return "unknown-process-limit"
		}
		processes = append(processes, entry)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return "unknown-process-enumeration"
	}
	descendants := map[uint32]bool{relayPID: true}
	recorded := map[uint32]bool{}
	var observations []string
	for range 3 {
		for _, process := range processes {
			if recorded[process.ProcessID] || process.ProcessID != relayPID && !descendants[process.ParentProcessID] {
				continue
			}
			if len(observations) == 16 {
				return "unknown-descendant-limit"
			}
			descendants[process.ProcessID] = true
			recorded[process.ProcessID] = true
			role := "client"
			if process.ProcessID == relayPID {
				role = "relay"
			} else if strings.EqualFold(windows.UTF16ToString(process.ExeFile[:]), "conhost.exe") {
				role = "conhost"
			}
			state := "unknown"
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, process.ProcessID)
			if err == nil {
				state = observeLocalConPTYRootState(func() (uint32, error) { return windows.WaitForSingleObject(handle, 0) })
				_ = windows.CloseHandle(handle)
			}
			observations = append(observations, fmt.Sprintf("role=%s pid=%d parent=%d threads=%d state=%s", role, process.ProcessID, process.ParentProcessID, process.Threads, state))
		}
	}
	if len(observations) == 0 {
		return "unobserved"
	}
	return strings.Join(observations, "; ")
}

func TestLocalConPTYClientProgressEventsAreIndependentOfConsoleOutput(t *testing.T) {
	t.Setenv("BIFROEST_TEST_CONPTY_CLIENT_PROGRESS", "1")
	progress := newLocalConPTYClientProgress(t)
	require.Equal(t, "unobserved", progress.snapshot())
	observe := localConPTYClientPhaseObserver(progress.prefix)
	for index, phase := range localConPTYClientProgressPhases {
		observe(phase)
		require.Equal(t, strings.Join(localConPTYClientProgressPhases[:index+1], ","), progress.snapshot())
	}
	before := progress.snapshot()
	observe("not-a-client-phase")
	require.Equal(t, before, progress.snapshot())
	var disabled *localConPTYClientProgress
	require.Equal(t, "disabled", disabled.snapshot())
	localConPTYClientPhaseObserver("")("client.entered")
}

func TestLocalConPTYProcessSnapshotObservesWithoutWaiting(t *testing.T) {
	snapshot := localConPTYTestProcessSnapshot(uint32(os.Getpid()))
	require.Regexp(t, fmt.Sprintf(`role=relay pid=%d parent=\d+ threads=\d+ state=running`, os.Getpid()), snapshot)
}
