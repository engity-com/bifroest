//go:build unix

package main

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/sys"
)

type execOpts struct {
	storeExitCodeForConnectionId bool
	exitCodeByConnectionIdPath   string
	connectionId                 connection.Id
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
	if plainUser := with.user; plainUser != "" {
		cmd.SysProcAttr.Credential = &syscall.Credential{}

		var u *user.User
		var err error
		if _, numericErr := strconv.ParseUint(plainUser, 10, 32); numericErr == nil {
			u, err = user.LookupId(plainUser)
		} else {
			u, err = user.Lookup(plainUser)
		}
		if err != nil {
			return err
		}
		if v, err := strconv.ParseUint(u.Uid, 10, 32); err != nil {
			return err
		} else {
			cmd.SysProcAttr.Credential.Uid = uint32(v)
		}

		if plainGroup := with.group; plainGroup != "" {
			var g *user.Group
			if _, numericErr := strconv.ParseUint(plainGroup, 10, 32); numericErr == nil {
				g, err = user.LookupGroupId(plainGroup)
			} else {
				g, err = user.LookupGroup(plainGroup)
			}
			if err != nil {
				return err
			}
			if v, err := strconv.ParseUint(g.Gid, 10, 32); err != nil {
				return err
			} else {
				cmd.SysProcAttr.Credential.Gid = uint32(v)
			}
		} else if v, err := strconv.ParseUint(u.Gid, 10, 32); err != nil {
			return err
		} else {
			cmd.SysProcAttr.Credential.Gid = uint32(v)
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
