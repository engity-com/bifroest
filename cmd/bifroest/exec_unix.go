//go:build unix

package main

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/errors"
)

type execOpts struct {
	workingDirectory string
	environment      map[string]string
	user, group      string
	path             string
	argv             []string
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
	if plainUser := with.user; plainUser != "" {
		cmd.SysProcAttr.Credential = &syscall.Credential{}

		u, err := user.LookupId(plainUser)
		var uuiErr *user.UnknownUserIdError
		if errors.As(err, &uuiErr) {
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
			g, err := user.LookupGroupId(plainGroup)
			var ugiErr *user.UnknownGroupIdError
			if errors.As(err, &ugiErr) {
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
		}
	}

	return nil
}
