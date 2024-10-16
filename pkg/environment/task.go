package environment

import (
	"fmt"

	"github.com/gliderlabs/ssh"
)

type TaskType uint8

const (
	TaskTypeShell TaskType = iota
	TaskTypeSftp
)

func (this TaskType) String() string {
	switch this {
	case TaskTypeShell:
		return "shell"
	case TaskTypeSftp:
		return "sftp"
	default:
		return fmt.Sprintf("illegal-task-type-%d", this)
	}
}

type Task interface {
	Context
	SshSession() ssh.Session
	TaskType() TaskType
}
