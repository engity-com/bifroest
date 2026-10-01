//go:build windows

package authorization

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/windowslocal"
)

type local struct {
	user                windowslocal.Account
	remote              net.Remote
	flow                configuration.FlowName
	session             session.Session
	sessionsPublicKey   ssh.PublicKey
	authorizedKeyPolicy *AuthorizedKeyPolicy
}

func (*local) AuthorizationKind() string                      { return "local" }
func (this *local) LocalWindowsIdentity() (string, string)    { return this.user.Name, this.user.SID }
func (this *local) Remote() net.Remote                        { return this.remote }
func (*local) IsAuthorized() bool                             { return true }
func (*local) EnvVars() sys.EnvVars                           { return nil }
func (this *local) Flow() configuration.FlowName              { return this.flow }
func (this *local) FindSession() session.Session              { return this.session }
func (this *local) FindSessionsPublicKey() ssh.PublicKey      { return this.sessionsPublicKey }
func (this *local) AuthorizedKeyPolicy() *AuthorizedKeyPolicy { return this.authorizedKeyPolicy }

func (this *local) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		if name == "user" {
			if resolver, ok := ce.(interface {
				ResolveLocalWindowsUserManaged(configuration.FlowName, windowslocal.Account) (bool, bool, error)
			}); ok {
				managed, available, err := resolver.ResolveLocalWindowsUserManaged(this.flow, this.user)
				if err != nil {
					return nil, false, err
				}
				if available {
					return localWindowsUserWithManagement{this.user, managed}, true, nil
				}
			}
			return this.user, true, nil
		}
		return nil, false, fmt.Errorf("unknown field %q", name)
	})
}

type localWindowsUserWithManagement struct {
	windowslocal.Account
	managed bool
}

func (this localWindowsUserWithManagement) GetField(name string) (any, bool, error) {
	if name == "managed" {
		return this.managed, true, nil
	}
	return this.Account.GetField(name)
}

func (this *local) Dispose(ctx context.Context) (bool, error) {
	if this.session == nil {
		return false, nil
	}
	if err := this.session.SetAuthorizationToken(ctx, nil); err != nil {
		return false, err
	}
	return true, nil
}

type localToken struct {
	User struct {
		Name string `json:"name"`
		SID  string `json:"sid"`
	} `json:"user"`
}
