package environment

import (
	"context"
	"io"
)

type Environment interface {
	Banner(Request) (io.ReadCloser, error)
	Run(Task) (int, error)

	IsPortForwardingAllowed(host string, port uint32) (bool, error)
	NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error)

	Release() error
	Dispose(context.Context) (bool, error)
}
