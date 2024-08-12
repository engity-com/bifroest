package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"time"
)

func (this *fsSession) Flow() configuration.FlowName {
	return this.VFlow.Clone()
}

func (this *fsSession) Id() uuid.UUID {
	var result uuid.UUID
	copy(result[:], this.VId[:])
	return result
}

func (this *fsSession) String() string {
	return this.Id().String()
}

func (this *fsSession) State() State {
	return this.VState
}

func (this *fsSession) Created() (InfoCreated, error) {
	return this, nil
}

func (this *fsSession) ValidUntil() (time.Time, error) {
	lastAccessed, err := this.LastAccessed()
	if err != nil {
		return time.Time{}, err
	}
	return lastAccessed.At().Add(this.repository.conf.IdleTimeout.Native()), nil
}

func (this *fsSession) LastAccessed() (InfoLastAccessed, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()

	r, _, err := this.repository.openRead(this.VFlow, this.VId, FsFileLastAccessed)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseError(r)

	buf := fsLastAccessed{
		session: this,
	}
	if err := json.NewDecoder(r).Decode(&buf); err != nil {
		return nil, fmt.Errorf("cannot decode last access of %v/%v: %w", this.VFlow, this.VId, err)
	}

	return &buf, nil
}
