package environment

import (
	"context"
	"github.com/engity-com/bifroest/pkg/session"
	"io"
)

type Environment interface {
	Session() session.Session

	Banner(Request) (io.ReadCloser, error)
	Run(Task) (int, error)

	IsPortForwardingAllowed(host string, port uint32) (bool, error)
	NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error)

	Dispose(context.Context) (bool, error)
}
