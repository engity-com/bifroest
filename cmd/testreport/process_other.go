//go:build !linux && !darwin && !windows

package main

import (
	"os"
	"os/exec"
)

func configureCommand(cmd *exec.Cmd) (func() error, func(), error) {
	return func() error { return nil }, func() {}, nil
}

func signalExitCode(*os.ProcessState) int    { return 1 }
func rss(*os.ProcessState) (*uint64, string) { return nil, "" }
