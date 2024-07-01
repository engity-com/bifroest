package authorization

import (
	"github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
	"github.com/gliderlabs/ssh"
	gssh "golang.org/x/crypto/ssh"
)

type Request interface {
	Sessions() session.Repository
	Context() ssh.Context
	Remote() common.Remote
	Logger() log.Logger
	Validate(Authorization) (bool, error)
}

type PublicKeyRequest interface {
	Request
	RemotePublicKey() gssh.PublicKey
}

type PasswordRequest interface {
	Request
	RemotePassword() string
}

type InteractiveRequest interface {
	Request
	SendInfo(string) error
	SendError(string) error
	Prompt(msg string, echoOn bool) (string, error)
}

type userEnabledRequest struct {
	Request
	user *user.User
}

func (this *userEnabledRequest) GetField(name string) (any, bool) {
	switch name {
	case "user":
		return this.user, true
	default:
		return nil, false
	}
}
