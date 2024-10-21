package authorization

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Authorization interface {
	IsAuthorized() bool
	EnvVars() sys.EnvVars
	Flow() configuration.FlowName
	Remote() net.Remote
	FindSession() session.Session
	FindSessionsPublicKey() ssh.PublicKey
	Dispose(context.Context) (bool, error)
}

func Forbidden(remote net.Remote) Authorization {
	return &forbiddenResponse{remote}
}

type forbiddenResponse struct {
	remote net.Remote
}

func (this forbiddenResponse) Remote() net.Remote {
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

func (this *forbiddenResponse) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		return nil, false, fmt.Errorf("unknown field %q", name)
	})
}
