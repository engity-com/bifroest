package session

import (
	glssh "github.com/engity-com/ssh-server-go"
)

type contextEnabled interface {
	Context() glssh.Context
}
