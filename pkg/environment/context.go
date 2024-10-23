package environment

import (
	glssh "github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
)

type Context interface {
	Connection() connection.Connection
	Context() glssh.Context
	Authorization() authorization.Authorization
}
