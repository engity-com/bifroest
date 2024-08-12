package environment

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/gliderlabs/ssh"
)

type Request interface {
	Remote() common.Remote
	Context() ssh.Context
	Logger() log.Logger
	Authorization() authorization.Authorization
	FindSession() session.Session
}
