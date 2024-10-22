package ssh

import (
	gonet "net"

	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const authAgentChannelName = "auth-agent@openssh.com"

func ForwardAgentConnections(ln gonet.Listener, logger log.Logger, sshSess ssh.Session) {
	ctx := sshSess.Context()
	sshConn := ctx.Value(ssh.ContextKeyConn).(gossh.Conn)
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
