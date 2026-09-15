//go:build !linux

package processidentity

import (
	"strconv"

	"github.com/shirou/gopsutil/v4/process"
)

// Get returns a value that identifies the current lifetime of a process.
func Get(pid int) (string, error) {
	candidate, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", err
	}
	createdAt, err := candidate.CreateTime()
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(createdAt, 10), nil
}

// Matches reports whether pid still refers to the recorded process lifetime.
func Matches(pid int, expected string) (bool, error) {
	actual, err := Get(pid)
	return actual == expected, err
}

// RequiresEnvironment reports whether an identity needs an additional check.
func RequiresEnvironment(string) bool { return false }
