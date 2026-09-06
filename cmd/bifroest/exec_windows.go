//go:build windows

package main

import (
	"os/exec"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

type execOpts struct {
	storeExitCodeForConnectionId bool
	exitCodeByConnectionIdPath   string
	connectionId                 connection.Id
	executionId                  execution.Id
	workingDirectory             string
	environment                  map[string]string
	path                         string
	argv                         []string
}

func registerExecCmdFlags(_ *kingpin.CmdClause, _ *execOpts) {
}

func enrichExecCmd(_ *exec.Cmd, _ *execOpts) error {
	return nil
}

func signalExecCmd(cmd *exec.Cmd, signal sys.Signal) error {
	if cmd.Process == nil {
		return nil
	}
	if signal == sys.SIGTERM || signal == sys.SIGKILL {
		return cmd.Process.Kill()
	}
	return signal.SendToProcess(cmd.Process)
}

func execExitCode(err *exec.ExitError) int {
	return err.ExitCode()
}
