package session

import (
	essh "github.com/engity-com/ssh-server-go"
)

type contextEnabled interface {
	Context() essh.Context
}
