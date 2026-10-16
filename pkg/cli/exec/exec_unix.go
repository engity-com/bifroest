//go:build unix

package exec

import (
	goos "os"
	"os/exec"
	"syscall"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

func execSignalsToForward() []goos.Signal {
	return []goos.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM}
}

type opts struct {
	StoreExitCodeForConnectionId bool              `flag:"storeExitCodeForConnectionId" short:"x" description:"Store this process' exit code under --exitCodeByConnectionIdPath; requires --executionId."`
	ExitCodeByConnectionIdPath   string            `flag:"exitCodeByConnectionIdPath" description:"Folder where exitCodes by their connectionId will be placed."`
	ConnectionId                 connection.Id     `flag:"connectionId" short:"c" description:"Connection ID this execution is connected to."`
	ExecutionId                  execution.Id      `flag:"executionId" description:"Unique ID of this execution."`
	WorkingDirectory             string            `flag:"workingDir" short:"d" description:"Directory to start in."`
	Environment                  map[string]string `flag:"env" short:"e" description:"Environment variables to execute the process with."`
	User                         string            `flag:"user" short:"u" description:"User the process should run with."`
	Group                        string            `flag:"group" short:"g" description:"Group the process should run with."`
	Executable                   string            `flag:"executable" short:"p" description:"Path to executable to be used. If not defined, first argument will be used."`
	Command                      []string          `argument:"command" required:"true" description:"Command to execute."`

	EncodedEnvironment string
}

func enrichExecCmd(cmd *exec.Cmd, with *opts) error {
	cmd.SysProcAttr.Setpgid = true
	if plainUser, plainGroup := with.User, with.Group; plainUser != "" || plainGroup != "" {
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
	return signal.SendToPid(-cmd.Process.Pid)
}

func execExitCode(err *exec.ExitError) int {
	if status, ok := err.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return err.ExitCode()
}
