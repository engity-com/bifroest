package managementclient

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

const defaultWindowsAgent = `\\.\pipe\openssh-ssh-agent`
const windowsAgentDialTimeout = 5 * time.Second

func connectAgent(ctx context.Context, identityAgent string) (agent.Agent, io.Closer, error) {
	if identityAgent == "none" {
		return nil, nil, nil
	}
	if identityAgent == "pageant" {
		if !pageantAvailable() {
			return nil, nil, fmt.Errorf("configured Pageant SSH agent is not running")
		}
		return agent.NewClient(&pageantConnection{}), nil, nil
	}
	path := identityAgent
	if path == "" {
		path = defaultWindowsAgent
	}
	if !strings.HasPrefix(strings.ToLower(path), `\\.\pipe\`) {
		return nil, nil, fmt.Errorf("unsupported Windows IdentityAgent %q: expected a named pipe", path)
	}
	dialCtx, stop := context.WithTimeout(ctx, windowsAgentDialTimeout)
	defer stop()
	conn, err := winio.DialPipeContext(dialCtx, path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
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
