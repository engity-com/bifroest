package managementclient

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

const defaultWindowsAgent = `\\.\pipe\openssh-ssh-agent`

func connectAgent(identityAgent string) (agent.Agent, io.Closer, error) {
	if identityAgent == "none" {
		return nil, nil, nil
	}
	path := identityAgent
	if path == "" {
		path = defaultWindowsAgent
	}
	if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
		return nil, nil, fmt.Errorf("unsupported Windows IdentityAgent %q: expected a named pipe", path)
	}
	conn, err := winio.DialPipeContext(context.Background(), path)
	if err != nil {
		if identityAgent == "" {
			if pageantAvailable() {
				return agent.NewClient(&pageantConnection{}), nil, nil
			}
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return agent.NewClient(conn), conn, nil
}
