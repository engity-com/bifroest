package environment

import (
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
)

type Context interface {
	connection.Context
	Authorization() authorization.Authorization
}
