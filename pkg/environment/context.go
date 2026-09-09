package environment

import (
	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
)

type Context interface {
	Connection() connection.Connection
	Context() essh.Context
	Authorization() authorization.Authorization
}
