//go:build !windows

package managementclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func connectAgent(ctx context.Context, identityAgent string) (agent.Agent, io.Closer, error) {
	if identityAgent == "none" {
		return nil, nil, nil
	}
	if identityAgent == "pageant" {
		return nil, nil, fmt.Errorf("pageant is only available on Windows")
	}
	path := identityAgent
	if path == "" {
		path = os.Getenv("SSH_AUTH_SOCK")
	}
	if path == "" {
		return nil, nil, nil
	}
	path, err := expandHome(path)
	if err != nil {
		return nil, nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot connect to SSH agent socket %q: %w", path, err)
	}
	client, closer := newAgentConnection(ctx, conn)
	return client, closer, nil
}
