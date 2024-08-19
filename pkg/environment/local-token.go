//go:build linux

package environment

import "github.com/engity-com/bifroest/pkg/user"

type localToken struct {
	User                  localTokenUser `json:"user"`
	PortForwardingAllowed bool           `json:"portForwardingAllowed"`
}

type localTokenUser struct {
	Name                   string   `json:"name,omitempty"`
	Uid                    *user.Id `json:"uid,omitempty"`
	Managed                bool     `json:"managed,omitempty"`
	DeleteOnDispose        bool     `json:"deleteOnDispose,omitempty"`
	DeleteHomeDirOnDispose bool     `json:"deleteHomeDirOnDispose,omitempty"`
	KillProcessesOnDispose bool     `json:"killProcessesOnDispose,omitempty"`
}
