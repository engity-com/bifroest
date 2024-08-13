package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
	"strings"
	"time"
)

type fsLastAccessed struct {
	session *fs

	VAt         time.Time `json:"at"`
	VRemoteUser string    `json:"remoteUser"`
	VRemoteAddr net.Host  `json:"remoteAddr"`
}

func (this *fsLastAccessed) String() string {
	return this.User() + "@" + this.VRemoteAddr.String()
}

func (this *fsLastAccessed) At() time.Time {
	return this.VAt
}

func (this *fsLastAccessed) Remote() common.Remote {
	return this
}

func (this *fsLastAccessed) User() string {
	return strings.Clone(this.VRemoteUser)
}

func (this *fsLastAccessed) Host() net.Host {
	return this.VRemoteAddr.Clone()
}

func (this *fsLastAccessed) save() error {
	f, _, err := this.session.repository.openWrite(this.session.VFlow, this.session.VId, FsFileLastAccessed, false)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v/%v: %w", this.session.VFlow, this.session.VId, err)
	}

	return nil
}
