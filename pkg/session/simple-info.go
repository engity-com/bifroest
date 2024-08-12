package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"time"
)

func (this *simple) Flow() configuration.FlowName {
	return this.flow.Clone()
}

func (this *simple) Id() uuid.UUID {
	return this.id
}

func (this *simple) String() string {
	return this.Id().String()
}

func (this *simple) State() State {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	return this.state
}

func (this *simple) Created() (InfoCreated, error) {
	return this, nil
}

func (this *simple) At() time.Time {
	return this.createdAt
}

func (this *simple) Remote() common.Remote {
	return this.createdBy
}

func (this *simple) LastAccessed() (InfoLastAccessed, error) {
	return &simpleLastAccessed{this}, nil
}

func (this *simple) ValidUntil() (time.Time, error) {
	return time.Time{}, nil
}
