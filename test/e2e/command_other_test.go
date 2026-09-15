//go:build e2e && !linux

package e2e_test

import "os/exec"

func configureCommandCancellation(*exec.Cmd) {}

func terminateCommandProcessGroup(*exec.Cmd) error { return nil }

func waitAndCleanupCommand(cmd *exec.Cmd) error { return cmd.Wait() }
