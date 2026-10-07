//go:build unix && !linux

package exec

import "os/exec"

type execProcessSupervisor struct{}

func newExecProcessSupervisor() (*execProcessSupervisor, error) { return &execProcessSupervisor{}, nil }
func (*execProcessSupervisor) Prepare(*exec.Cmd) error          { return nil }
func (*execProcessSupervisor) Attach(*exec.Cmd) error           { return nil }
func (*execProcessSupervisor) Cleanup() error                   { return nil }
