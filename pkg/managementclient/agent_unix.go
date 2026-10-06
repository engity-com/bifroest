//go:build !windows

package managementclient

import (
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func connectAgent(identityAgent string) (agent.Agent, io.Closer, error) {
	if identityAgent == "none" {
		return nil, nil, nil
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
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot connect to SSH agent socket %q: %w", path, err)
	}
	return agent.NewClient(conn), conn, nil
}
