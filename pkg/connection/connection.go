package connection

import (
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
