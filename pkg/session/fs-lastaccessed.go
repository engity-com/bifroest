package session

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/net"
	"os"
	"strings"
	"time"
)

type fsLastAccessed struct {
	info *fsInfo

	at          time.Time
	VRemoteUser string   `json:"remoteUser"`
	VRemoteHost net.Host `json:"remoteHost"`

	remote fsLastAccessedRemote
}

func (this *fsLastAccessed) init(info *fsInfo) {
	this.info = info
	this.remote.init(this)
}

func (this *fsLastAccessed) GetField(name string) (any, bool, error) {
	switch name {
	case "at":
		return this.at, true, nil
	case "remote":
		return this.Remote(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *fsLastAccessed) At() time.Time {
	return this.at
}

func (this *fsLastAccessed) Remote() common.Remote {
	return &this.remote
}

func (this *fsLastAccessed) save(_ context.Context) error {
	if _, err := this.info.stat(); err != nil {
		return fmt.Errorf("cannot session's %v last access because cannot stat info: %w", this, err)
	}

	f, _, err := this.info.session.repository.openWrite(this.info.session.flow, this.info.session.id, FsFileLastAccessed, false)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v: %w", this.info.session, err)
	}
	if err := os.Chtimes(f.Name(), time.Now(), this.at); err != nil {
		return fmt.Errorf("cannot change time of session's last access %v: %w", this, err)
	}

	return nil
}

type fsLastAccessedRemote struct {
	lastAccessed *fsLastAccessed
}

func (this *fsLastAccessedRemote) init(lastAccessed *fsLastAccessed) {
	this.lastAccessed = lastAccessed
}

func (this *fsLastAccessedRemote) String() string {
	return this.User() + "@" + this.Host().String()
}

func (this *fsLastAccessedRemote) User() string {
	return strings.Clone(this.lastAccessed.info.VRemoteUser)
}

func (this *fsLastAccessedRemote) Host() net.Host {
	return this.lastAccessed.info.VRemoteHost.Clone()
}

func (this *fsLastAccessedRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return this.User(), true, nil
	case "host":
		return this.Host(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}
