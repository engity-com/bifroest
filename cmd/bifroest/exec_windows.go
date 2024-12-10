//go:build windows

package main

import (
	"os/exec"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/connection"
)

type execOpts struct {
	storeExitCodeForConnectionId bool
	exitCodeByConnectionIdPath   string
	connectionId                 connection.Id
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
