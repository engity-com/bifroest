//go:build windows

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
	return []goos.Signal{syscall.SIGINT, syscall.SIGTERM}
}

type opts struct {
	StoreExitCodeForConnectionId bool              `flag:"storeExitCodeForConnectionId" short:"x" description:"Store this process' exit code under --exitCodeByConnectionIdPath; requires --executionId."`
	ExitCodeByConnectionIdPath   string            `flag:"exitCodeByConnectionIdPath" description:"Folder where exitCodes by their connectionId will be placed."`
	ConnectionId                 connection.Id     `flag:"connectionId" short:"c" description:"Connection ID this execution is connected to."`
	ExecutionId                  execution.Id      `flag:"executionId" description:"Unique ID of this execution."`
	WorkingDirectory             string            `flag:"workingDir" short:"d" description:"Directory to start in."`
	Environment                  map[string]string `flag:"env" short:"e" description:"Environment variables to execute the process with."`
	Executable                   string            `flag:"executable" short:"p" description:"Path to executable to be used. If not defined, first argument will be used."`
	Command                      []string          `flag:"command" required:"true" description:"Command to execute."`

	EncodedEnvironment string
}

func enrichExecCmd(_ *exec.Cmd, _ *opts) error {
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
