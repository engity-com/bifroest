package session

import (
	glssh "github.com/gliderlabs/ssh"
)

type contextEnabled interface {
	Context() glssh.Context
}
