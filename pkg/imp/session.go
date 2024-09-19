package imp

import (
	"io"
	"net"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/sys"
)

type Session interface {
	io.Closer
	Echo(connectionId uuid.UUID, in string) (out string, _ error)
	InitiateDirectTcp(connectionId uuid.UUID, host string, port uint32) (net.Conn, error)
	InitiateAgentForward(connectionId uuid.UUID) (_ net.Conn, socketPath string, _ error)
	Kill(connectionId uuid.UUID, pid int, signal sys.Signal) error
	Exit(connectionId uuid.UUID, exitCode int) error
}
