package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"time"
)

const (
	FsFileSession          = "se.json"
	FsFileLastAccessed     = "la.json"
	FsFileAccessToken      = "at"
	FsFilePublicKeysPrefix = "k-"
	FsFilePublicKeysSuffix = ".pubs"
)

type fs struct {
	repository *FsRepository

	VFlow  configuration.FlowName `json:"flow"`
	VId    uuid.UUID              `json:"id"`
	VState State                  `json:"state"`

	VCreatedAt  time.Time `json:"createdAt"`
	VRemoteUser string    `json:"remoteUser"`
	VRemoteHost net.Host  `json:"remoteHost"`
}

func (this *fs) Info() (Info, error) {
	return this, nil
}

func (this *fs) AuthorizationToken() (_ []byte, rErr error) {
	f, fn, err := this.repository.openRead(this.VFlow, this.VId, FsFileAccessToken)
	if sys.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer common.KeepCloseError(&rErr, f)

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
	}
	return data, nil
}

func (this *fs) SetAuthorizationToken(data []byte) (rErr error) {
	if len(data) == 0 {
		fn, err := this.repository.file(this.VFlow, this.VId, FsFileAccessToken)
		if err != nil {
			return fmt.Errorf("cannot delete session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
		}
		if err := os.Remove(fn); err != nil && !sys.IsNotExist(err) {
			return fmt.Errorf("cannot delete session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
		}
		return nil
	}

	f, fn, err := this.repository.openWrite(this.VFlow, this.VId, FsFileAccessToken, false)
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("cannot write session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
	}
	return nil
}

func (this *fs) HasPublicKey(pub ssh.PublicKey) (bool, error) {
	return this.repository.hasPublicKey(this.VFlow, this.VId, pub)
}

func (this *fs) AddPublicKey(pub ssh.PublicKey) error {
	return this.repository.addPublicKey(this.VFlow, this.VId, pub)
}

func (this *fs) DeletePublicKey(pub ssh.PublicKey) error {
	return this.repository.deletePublicKey(this.VFlow, this.VId, pub)
}

func (this *fs) NotifyLastAccess(remote common.Remote, newState State) error {
	buf := fsLastAccessed{
		session:     this,
		VAt:         time.Now().Truncate(time.Millisecond),
		VRemoteUser: remote.User(),
		VRemoteAddr: remote.Host().Clone(),
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

func (this *fs) save() error {
	f, _, err := this.repository.openWrite(this.VFlow, this.VId, FsFileSession, false)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v/%v: %w", this.VFlow, this.VId, err)
	}

	return nil
}
