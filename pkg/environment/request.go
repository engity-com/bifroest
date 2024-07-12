package environment

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/yasshd/pkg/authorization"
	"github.com/engity-com/yasshd/pkg/common"
	"github.com/gliderlabs/ssh"
)

type Request interface {
	Remote() common.Remote
	Context() ssh.Context
	Logger() log.Logger
	Authorization() authorization.Authorization
}
