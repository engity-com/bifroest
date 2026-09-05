//go:build unix

package main

import (
	"os/exec"
	"syscall"

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
	user, group                  string
	path                         string
	argv                         []string
}

func registerExecCmdFlags(cmd *kingpin.CmdClause, opts *execOpts) {
	cmd.Flag("user", "User the process should run with.").
		Default(opts.user).
		Short('u').
		StringVar(&opts.user)
	cmd.Flag("group", "Group the process should run with.").
		Default(opts.group).
		Short('g').
		StringVar(&opts.group)
}

func enrichExecCmd(cmd *exec.Cmd, with *execOpts) error {
	cmd.SysProcAttr.Setpgid = true
	if plainUser, plainGroup := with.user, with.group; plainUser != "" || plainGroup != "" {
		cmd.SysProcAttr.Credential = &syscall.Credential{}
		if err := sys.EnrichCredentials(cmd.SysProcAttr.Credential, plainUser, plainGroup); err != nil {
			return err
		}
	}

	return nil
}

func signalExecCmd(cmd *exec.Cmd, signal sys.Signal) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, signal.Native())
}

func execExitCode(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return err.ExitCode()
}
