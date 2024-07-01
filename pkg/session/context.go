package session

import (
	"github.com/gliderlabs/ssh"
)

type contextEnabled interface {
	Context() ssh.Context
}
