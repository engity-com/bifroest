package ssh

import (
	gonet "net"

	log "github.com/echocat/slf4g"
	glssh "github.com/engity-com/ssh-server-go"
)

const AuthSockEnvName = "SSH_AUTH_SOCK"

func AgentRequested(sshSess glssh.Session) bool {
	return glssh.AgentRequested(sshSess)
}

func ForwardAgentConnections(ln gonet.Listener, logger log.Logger, sshSess glssh.Session) {
	glssh.ForwardAgentConnections(ln, logger, sshSess)
}
