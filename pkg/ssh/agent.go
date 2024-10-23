package ssh

import (
	gonet "net"

	log "github.com/echocat/slf4g"
	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	AuthSockEnvName = "SSH_AUTH_SOCK"

	authAgentChannelName = "auth-agent@openssh.com"
)

func AgentRequested(sshSess glssh.Session) bool {
	return glssh.AgentRequested(sshSess)
}

func ForwardAgentConnections(ln gonet.Listener, logger log.Logger, sshSess glssh.Session) {
	ctx := sshSess.Context()
	sshConn := ctx.Value(glssh.ContextKeyConn).(gossh.Conn)
	for {
		conn, err := ln.Accept()
		if sys.IsClosedError(err) {
			return
		}
		if err != nil {
			logger.WithError(err).
				Warnf("failed to listen for %s channel connections; closing...", authAgentChannelName)
			return
		}
		go func(conn gonet.Conn) {
			defer common.IgnoreCloseError(conn)
			channel, reqs, err := sshConn.OpenChannel(authAgentChannelName, nil)
			if err != nil {
				logger.WithError(err).
					Warnf("failed to open %s channel; rejecting...", authAgentChannelName)
				return
			}
			defer common.IgnoreCloseError(channel)
			go gossh.DiscardRequests(reqs)
			if err := sys.FullDuplexCopy(ctx, conn, channel, &sys.FullDuplexCopyOpts{}); err != nil {
				logger.WithError(err).
					Warnf("failed to handle %s requests; closing...", authAgentChannelName)
				return
			}
		}(conn)
	}
}
