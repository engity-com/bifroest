package environment

import (
	"github.com/gliderlabs/ssh"
)

type TaskType uint8

const (
	TaskTypeShell TaskType = iota
	TaskTypeSftp
)

type Task interface {
	Request
	SshSession() ssh.Session
	TaskType() TaskType
}
