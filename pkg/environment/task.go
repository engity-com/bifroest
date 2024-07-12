package environment

import (
	"github.com/gliderlabs/ssh"
)

type Task interface {
	Request
	Session() ssh.Session
}
