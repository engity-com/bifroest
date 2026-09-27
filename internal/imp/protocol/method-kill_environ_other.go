//go:build !darwin

package protocol

import "github.com/shirou/gopsutil/v4/process"

func processEnviron(candidate *process.Process) ([]string, error) {
	return candidate.Environ()
}
