//go:build linux

package processidentity

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

// Get returns the boot ID and process start time in clock ticks since boot.
func Get(pid int) (string, error) {
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	startTime, err := parseLinuxStat(raw)
	if err != nil {
		return "", err
	}
	return "linux:" + strings.TrimSpace(string(bootID)) + ":" + strconv.FormatInt(startTime, 10), nil
}

// Matches reports whether pid still refers to the recorded process lifetime.
func Matches(pid int, expected string) (bool, error) {
	if strings.HasPrefix(expected, "linux:") {
		actual, err := Get(pid)
		return actual == expected, err
	}

	// Registrations written before Linux identities were versioned contain the
	// gopsutil creation time. Keep them readable while active executions drain.
	candidate, err := process.NewProcess(int32(pid))
	if err != nil {
		return false, err
	}
	createdAt, err := candidate.CreateTime()
	if err != nil {
		return false, err
	}
	return strconv.FormatInt(createdAt, 10) == expected, nil
}

// RequiresEnvironment reports whether an identity uses the legacy format,
// which is not safe across host reboots without an additional process check.
func RequiresEnvironment(identity string) bool {
	return !strings.HasPrefix(identity, "linux:")
}

func parseLinuxStat(raw []byte) (int64, error) {
	// The command name can contain spaces and closing parentheses, so split at
	// the final delimiter before the remaining fixed-position fields.
	endCommand := strings.LastIndex(string(raw), ") ")
	if endCommand < 0 {
		return 0, fmt.Errorf("invalid process stat format")
	}
	fields := strings.Fields(string(raw[endCommand+2:]))
	const startTimeIndex = 19 // field 22, relative to field 3 after the command
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("process stat has %d fields after command, expected at least %d", len(fields), startTimeIndex+1)
	}
	startTime, err := strconv.ParseInt(fields[startTimeIndex], 10, 64)
	if err != nil || startTime < 0 {
		return 0, fmt.Errorf("invalid process start time %q", fields[startTimeIndex])
	}
	return startTime, nil
}
