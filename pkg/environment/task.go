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
	Session() ssh.Session
	TaskType() TaskType
}
