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
	Ping(ctx context.Context, connectionId connection.Id) error
	InitiateTcpForward(ctx context.Context, connectionId connection.Id, target net.HostPort) (gonet.Conn, error)
	InitiateNamedPipe(ctx context.Context, connectionId connection.Id, purpose net.Purpose) (net.NamedPipe, error)

	// GetConnectionExitCode will return either the exitCode (if found)
	// or [connection.ErrNotFound] if the corresponding connection can't be found.
	GetConnectionExitCode(ctx context.Context, connectionId connection.Id) (int, error)

	GetEnvironment(ctx context.Context, connectionId connection.Id) (sys.EnvVars, error)

	// Kill will try to kill the process with the given signal.
	// If pid is 0, the process will be resolved by its connection.EnvVar that is matching the provided
	// connectionId.
	Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error
}
