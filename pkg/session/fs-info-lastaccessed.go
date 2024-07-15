package session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type fsLastAccessed struct {
	session *fsSession

	VAt         time.Time `json:"at"`
	VRemoteUser string    `json:"remoteUser"`
	VRemoteAddr net.IP    `json:"remoteAddr"`
}

func (this *fsLastAccessed) At() time.Time {
	return this.VAt
}

func (this *fsLastAccessed) RemoteUser() string {
	return strings.Clone(this.VRemoteUser)
}

func (this *fsLastAccessed) RemoteAddr() net.IP {
	return bytes.Clone(this.VRemoteAddr)
}

func (this *fsLastAccessed) save() error {
	f, _, err := this.session.repository.openWrite(this.session.VFlow, this.session.VId, FsFileLastAccessed)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v/%v: %w", this.session.VFlow, this.session.VId, err)
	}

	return nil
}
