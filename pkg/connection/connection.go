package connection

import (
	"context"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
)

const (
	EnvName = "BIFROEST_CONNECTION_ID"
)

var (
	ErrNotFound = errors.System.Newf("connection not found")
)

type Connection interface {
	Id() Id
	Remote() net.Remote
	Logger() log.Logger
}

// LifetimeAware is implemented by connections that expose their complete
// lifetime independently of individual channel or session contexts.
type LifetimeAware interface {
	Connection
	Lifetime() context.Context
}
