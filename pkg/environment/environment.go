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

	// Dispose will fully dispose this instance.
	// It does also implicitly call Close() to ensure everything happens
	// in the correct synchronized context.
	Dispose(context.Context) (bool, error)

	// Close can be safely called more than once.
	Close() error
}
