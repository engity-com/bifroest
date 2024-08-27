package environment

import (
	"context"
	"io"

	"github.com/engity-com/bifroest/pkg/session"
)

type Environment interface {
	Session() session.Session

	Banner(Request) (io.ReadCloser, error)
	Run(Task) (int, error)

	IsPortForwardingAllowed(host string, port uint32) (bool, error)
	NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error)

	Dispose(context.Context) (bool, error)
}
