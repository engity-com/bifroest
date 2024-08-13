package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"sync"
	"time"
)

type simple struct {
	flow           configuration.FlowName
	id             uuid.UUID
	state          State
	createdAt      time.Time
	createdBy      common.Remote
	lastAccessedAt time.Time
	lastAccessedBy common.Remote

	mutex sync.RWMutex
}

func (this *simple) Info() (Info, error) {
	return this, nil
}

func (this *simple) AuthorizationToken() ([]byte, error) {
	return nil, nil
}

func (this *simple) SetAuthorizationToken([]byte) (rErr error) {
	return nil
}

func (this *simple) HasPublicKey(ssh.PublicKey) (bool, error) {
	return false, nil
}

func (this *simple) AddPublicKey(ssh.PublicKey) error {
	return nil
}

func (this *simple) DeletePublicKey(ssh.PublicKey) error {
	return nil
}

func (this *simple) NotifyLastAccess(remote common.Remote, state State) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.lastAccessedAt = time.Now()
	this.lastAccessedBy = remote
	if state != StateUnchanged {
		this.state = state
	}
	return nil
}
