package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

const (
	FsFileSession      = "se.json"
	FsFileLastAccessed = "la.json"
)

type fsSession struct {
	repository *FsRepository

	VFlow  configuration.FlowName `json:"flow"`
	VId    uuid.UUID              `json:"id"`
	VState State                  `json:"state"`

	VCreatedAt  time.Time `json:"createdAt"`
	VRemoteUser string    `json:"remoteUser"`
	VRemoteAddr net.IP    `json:"remoteAddr"`
}

func (this *fsSession) Info() (Info, error) {
	return this, nil
}

func (this *fsSession) PublicKeys(consumer func(key ssh.PublicKey) (canContinue bool, err error)) error {
	//TODO implement me
	panic("implement me")
}

func (this *fsSession) AddPublicKey(key ssh.PublicKey) error {
	//TODO implement me
	panic("implement me")
}

func (this *fsSession) NotifyLastAccess(remoteUser string, remoteAddr net.IP, newState State) error {
	buf := fsLastAccessed{
		session:     this,
		VAt:         time.Now().Truncate(time.Millisecond),
		VRemoteUser: remoteUser,
		VRemoteAddr: remoteAddr,
	}
	if err := buf.save(); err != nil {
		return err
	}
	if newState != 0 && newState != this.VState {
		this.VState = newState
		if err := buf.save(); err != nil {
			return err
		}
	}
	return nil
}

func (this *fsSession) save() error {
	f, _, err := this.repository.openWrite(this.VFlow, this.VId, FsFileSession)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v/%v: %w", this.VFlow, this.VId, err)
	}

	return nil
}
