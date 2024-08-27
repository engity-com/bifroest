package environment

import (
	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
)

type Request interface {
	Remote() common.Remote
	Context() ssh.Context
	Logger() log.Logger
	Authorization() authorization.Authorization
}
