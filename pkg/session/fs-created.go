package session

import (
	"fmt"
	"strings"
	"time"

	"github.com/engity-com/bifroest/pkg/net"
)

type fsCreated struct {
	info *fsInfo

	remote fsCreatedRemote
}

func (this *fsCreated) init(info *fsInfo) {
	this.info = info
	this.remote.init(this)
}

func (this *fsCreated) At() time.Time {
	return this.info.createdAt
}

func (this *fsCreated) Remote() net.Remote {
	return &this.remote
}

func (this *fsCreated) GetField(name string) (any, bool, error) {
	switch name {
	case "at":
		return this.At(), true, nil
	case "remote":
		return this.Remote(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

type fsCreatedRemote struct {
	created *fsCreated
}

func (this *fsCreatedRemote) init(created *fsCreated) {
	this.created = created
}

func (this *fsCreatedRemote) String() string {
	return this.User() + "@" + this.Host().String()
}

func (this *fsCreatedRemote) User() string {
	return strings.Clone(this.created.info.VRemoteUser)
}

func (this *fsCreatedRemote) Host() net.Host {
	return this.created.info.VRemoteHost.Clone()
}

func (this *fsCreatedRemote) GetField(name string) (any, bool, error) {
	switch name {
	case "user":
		return this.User(), true, nil
	case "host":
		return this.Host(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}
