package environment

import (
	"context"
	"io"

	"github.com/engity-com/bifroest/pkg/net"
)

type Environment interface {
	Banner(Request) (io.ReadCloser, error)
	Run(Task) (int, error)

	IsPortForwardingAllowed(net.HostPort) (bool, error)
	NewDestinationConnection(context.Context, net.HostPort) (io.ReadWriteCloser, error)

	// Dispose will fully dispose this instance.
	// It does also implicitly call Close() to ensure everything happens
	// in the correct synchronized context.
	Dispose(context.Context) (bool, error)

	// Close can be safely called more than once.
	Close() error
}

// ReversePortForwardingPolicy allows an environment to specialize reverse
// forwarding independently from local and dynamic forwarding.
type ReversePortForwardingPolicy interface {
	IsReversePortForwardingAllowed(net.HostPort) (bool, error)
}
