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

type none struct {
	remote            net.Remote
	envVars           sys.EnvVars
	flow              configuration.FlowName
	session           session.Session
	sessionsPublicKey ssh.PublicKey
}

func (this *none) Remote() net.Remote {
	return this.remote
}

func (this *none) IsAuthorized() bool {
	return true
}

func (this *none) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *none) Flow() configuration.FlowName {
	return this.flow
}

func (this *none) FindSession() session.Session {
	return this.session
}

func (this *none) FindSessionsPublicKey() ssh.PublicKey {
	return this.sessionsPublicKey
}

func (this *none) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		return nil, false, fmt.Errorf("unknown field %q", name)
	})
}

func (this *none) Dispose(context.Context) (bool, error) {
	sess := this.session
	if sess == nil {
		return false, nil
	}
	return true, nil
}
