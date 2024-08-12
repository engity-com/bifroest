package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
	"strings"
	"time"
)

func (this *fsSession) At() time.Time {
	return this.VCreatedAt
}

func (this *fsSession) Remote() common.Remote {
	return fsSessionRemote{this}
}

type fsSessionRemote struct {
	*fsSession
}

func (this fsSessionRemote) String() string {
	return this.User() + "@" + this.Host().String()
}

func (this fsSessionRemote) User() string {
	return strings.Clone(this.VRemoteUser)
}

func (this fsSessionRemote) Host() net.Host {
	return this.VRemoteHost.Clone()
}
