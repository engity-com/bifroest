package connection

import "context"

// Context is the transport-independent context shared by authorization and
// environment requests. Protocol-specific capabilities belong to their adapters,
// not to the lifetime context of every request.
type Context interface {
	Context() context.Context
	Connection() Connection
}
