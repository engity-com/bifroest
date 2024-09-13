//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func adjustImpCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
