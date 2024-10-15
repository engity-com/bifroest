package imp

import (
	"context"
	"io"
	"net"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Session interface {
	io.Closer
	Echo(ctx context.Context, connectionId connection.Id, in string) (out string, _ error)
	InitiateDirectTcp(ctx context.Context, connectionId connection.Id, host string, port uint32) (net.Conn, error)
	InitiateAgentForward(ctx context.Context, connectionId connection.Id) (_ net.Conn, socketPath string, _ error)
	Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error
	Exit(ctx context.Context, connectionId connection.Id, exitCode int) error
}
