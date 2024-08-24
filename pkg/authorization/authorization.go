package authorization

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Authorization interface {
	IsAuthorized() bool
	EnvVars() sys.EnvVars
	Flow() configuration.FlowName
	Remote() common.Remote
	FindSession() session.Session
	FindSessionsPublicKey() ssh.PublicKey
	Dispose(context.Context) (bool, error)
}

func Forbidden(remote common.Remote) Authorization {
	return &forbiddenResponse{remote}
}

type forbiddenResponse struct {
	remote common.Remote
}

func (this forbiddenResponse) Remote() common.Remote {
	return this.remote
}

func (this forbiddenResponse) IsAuthorized() bool {
	return false
}

func (this forbiddenResponse) EnvVars() sys.EnvVars {
	return nil
}

func (this forbiddenResponse) Flow() configuration.FlowName {
	return ""
}

func (this forbiddenResponse) FindSessionsPublicKey() ssh.PublicKey {
	return nil
}

func (this forbiddenResponse) FindSession() session.Session {
	return nil
}

func (this forbiddenResponse) Dispose(context.Context) (bool, error) {
	return false, nil
}
