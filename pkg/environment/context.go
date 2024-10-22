package environment

import (
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
)

type Context interface {
	Connection() connection.Connection
	Context() ssh.Context
	Authorization() authorization.Authorization
}
