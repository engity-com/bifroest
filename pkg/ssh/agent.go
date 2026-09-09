package ssh

import (
	gonet "net"

	log "github.com/echocat/slf4g"
	essh "github.com/engity-com/ssh-server-go"
)

const AuthSockEnvName = "SSH_AUTH_SOCK"

func AgentRequested(sshSess essh.Session) bool {
	return essh.AgentRequested(sshSess)
}

func ForwardAgentConnections(ln gonet.Listener, logger log.Logger, sshSess essh.Session) {
	essh.ForwardAgentConnections(ln, logger, sshSess)
}
