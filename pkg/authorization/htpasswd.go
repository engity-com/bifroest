package authorization

import (
	"context"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"golang.org/x/crypto/ssh"
)

type htpasswd struct {
	remote            common.Remote
	envVars           sys.EnvVars
	flow              configuration.FlowName
	session           session.Session
	sessionsPublicKey ssh.PublicKey
}

func (this *htpasswd) Remote() common.Remote {
	return this.remote
}

func (this *htpasswd) IsAuthorized() bool {
	return true
}

func (this *htpasswd) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *htpasswd) Flow() configuration.FlowName {
	return this.flow
}

func (this *htpasswd) FindSession() session.Session {
	return this.session
}

func (this *htpasswd) FindSessionsPublicKey() ssh.PublicKey {
	return this.sessionsPublicKey
}

func (this *htpasswd) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		switch name {
		case "user":
			return this.Remote(), true, nil
		default:
			return nil, false, fmt.Errorf("unknown field %q", name)
		}
	})
}

func (this *htpasswd) Dispose(ctx context.Context) (bool, error) {
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

type htpasswdToken struct {
	User    htpasswdTokenUser `json:"user"`
	EnvVars sys.EnvVars       `json:"envVars,omitempty"`
}

type htpasswdTokenUser struct {
	Name string `json:"name,omitempty"`
}
