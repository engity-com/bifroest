package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"time"
)

func (this *fs) Flow() configuration.FlowName {
	return this.VFlow.Clone()
}

func (this *fs) Id() uuid.UUID {
	var result uuid.UUID
	copy(result[:], this.VId[:])
	return result
}

func (this *fs) String() string {
	return this.Id().String()
}

func (this *fs) State() State {
	return this.VState
}

func (this *fs) Created() (InfoCreated, error) {
	return this, nil
}

func (this *fs) ValidUntil() (time.Time, error) {
	lastAccessed, err := this.LastAccessed()
	if err != nil {
		return time.Time{}, err
	}
	return lastAccessed.At().Add(this.repository.conf.IdleTimeout.Native()), nil
}

func (this *fs) lastAccessed() (*fsLastAccessed, error) {
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

func (this *fs) LastAccessed() (InfoLastAccessed, error) {
	return this.lastAccessed()
}
