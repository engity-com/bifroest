//go:build unix

package authorization

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

type local struct {
	user              *user.User
	remote            net.Remote
	envVars           sys.EnvVars
	flow              configuration.FlowName
	session           session.Session
	sessionsPublicKey ssh.PublicKey
}

func (this *local) Remote() net.Remote {
	return this.remote
}

func (this *local) IsAuthorized() bool {
	return true
}

func (this *local) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *local) Flow() configuration.FlowName {
	return this.flow
}

func (this *local) FindSession() session.Session {
	return this.session
}

func (this *local) FindSessionsPublicKey() ssh.PublicKey {
	return this.sessionsPublicKey
}

func (this *local) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		switch name {
		case "user":
			return this.user, true, nil
		default:
			return nil, false, fmt.Errorf("unknown field %q", name)
		}
	})
}

func (this *local) Dispose(ctx context.Context) (bool, error) {
	sess := this.session
	if sess == nil {
		return false, nil
	}

	// Delete myself from my session.
	if err := sess.SetAuthorizationToken(ctx, nil); err != nil {
		return false, err
	}

	return true, nil
}

type localToken struct {
	User    localTokenUser `json:"user"`
	EnvVars sys.EnvVars    `json:"envVars,omitempty"`
}

type localTokenUser struct {
	Name string   `json:"name,omitempty"`
	Uid  *user.Id `json:"uid,omitempty"`
}
