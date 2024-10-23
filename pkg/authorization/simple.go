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

type simple struct {
	entry             *configuration.AuthorizationSimpleEntry
	remote            net.Remote
	envVars           sys.EnvVars
	flow              configuration.FlowName
	session           session.Session
	sessionsPublicKey ssh.PublicKey
}

func (this *simple) Remote() net.Remote {
	return this.remote
}

func (this *simple) IsAuthorized() bool {
	return true
}

func (this *simple) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *simple) Flow() configuration.FlowName {
	return this.flow
}

func (this *simple) FindSession() session.Session {
	return this.session
}

func (this *simple) FindSessionsPublicKey() ssh.PublicKey {
	return this.sessionsPublicKey
}

func (this *simple) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		switch name {
		case "entry":
			return this.entry, true, nil
		default:
			return nil, false, fmt.Errorf("unknown field %q", name)
		}
	})
}

func (this *simple) Dispose(ctx context.Context) (bool, error) {
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

type simpleToken struct {
	User    simpleTokenUser `json:"user"`
	EnvVars sys.EnvVars     `json:"envVars,omitempty"`
}

type simpleTokenUser struct {
	Name string `json:"name,omitempty"`
}
