package imp

import (
	"context"
	"io"
	gonet "net"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Session interface {
	io.Closer
	Ping(ctx context.Context, connectionId connection.Id) error
	InitiateTcpForward(ctx context.Context, connectionId connection.Id, target net.HostPort) (gonet.Conn, error)
	InitiateNamedPipe(ctx context.Context, connectionId connection.Id, purpose net.Purpose) (net.NamedPipe, error)

	// GetConnectionExitCode returns the legacy connection-scoped exit code, or
	// [connection.ErrNotFound] if its result is not available yet.
	GetConnectionExitCode(ctx context.Context, connectionId connection.Id) (int, error)

	GetEnvironment(ctx context.Context, connectionId connection.Id) (sys.EnvVars, error)

	// Kill will try to kill the process with the given signal.
	// If pid is 0, the process will be resolved from the provided connection ID.
	Kill(ctx context.Context, connectionId connection.Id, pid int, signal sys.Signal) error
}

type ExecutionSession interface {
	Session
	InitiateNamedPipeForUser(ctx context.Context, connectionId connection.Id, purpose net.Purpose, user, group string) (net.NamedPipe, error)

	// GetExecutionExitCode returns the exit code for one execution, or
	// [connection.ErrNotFound] if its result is not available yet.
	GetExecutionExitCode(ctx context.Context, connectionId connection.Id, executionId execution.Id) (int, error)

	// KillExecution will try to kill the process with the given signal.
	// If pid is 0, the process will be resolved from the provided execution ID.
	KillExecution(ctx context.Context, connectionId connection.Id, executionId execution.Id, pid int, signal sys.Signal) error
}
