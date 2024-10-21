package imp

import (
	"context"
	"io"
	gonet "net"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Session interface {
	io.Closer
	Echo(ctx context.Context, connectionId connection.Id, in string) (out string, _ error)
	InitiateTcpForward(ctx context.Context, connectionId connection.Id, target net.HostPort) (gonet.Conn, error)
	InitiateNamedPipe(ctx context.Context, connectionId connection.Id, purpose net.Purpose) (net.NamedPipe, error)
	Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error
	Exit(ctx context.Context, connectionId connection.Id, exitCode int) error
}
