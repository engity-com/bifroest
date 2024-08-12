package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"time"
)

type simpleLastAccessed struct {
	parent *simple
}

func (this *simpleLastAccessed) At() time.Time {
	this.parent.mutex.RLock()
	defer this.parent.mutex.RUnlock()
	return this.parent.lastAccessedAt
}

func (this *simpleLastAccessed) Remote() common.Remote {
	this.parent.mutex.RLock()
	defer this.parent.mutex.RUnlock()
	return this.parent.lastAccessedBy
}
