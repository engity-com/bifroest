package managementclient

import (
	"context"
	"io"
	"sync"

	"golang.org/x/crypto/ssh/agent"
)

// Close an agent connection when the command is canceled, including while a
// signers or signing request is waiting for a response from the agent.
type managedAgentConnection struct {
	connection io.ReadWriteCloser
	stop       func() bool
	once       sync.Once
	closeErr   error
}

func (this *managedAgentConnection) close() error {
	this.once.Do(func() { this.closeErr = this.connection.Close() })
	return this.closeErr
}

func (this *managedAgentConnection) Close() error {
	this.stop()
	return this.close()
}

func newAgentConnection(ctx context.Context, connection io.ReadWriteCloser) (agent.Agent, io.Closer) {
	managed := &managedAgentConnection{connection: connection}
	managed.stop = context.AfterFunc(ctx, func() { _ = managed.close() })
	return agent.NewClient(connection), managed
}
