package environment

import (
	glssh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
)

type Context interface {
	Connection() connection.Connection
	Context() glssh.Context
	Authorization() authorization.Authorization
}
