package session

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/google/uuid"
	"os"
	"time"
)

type fsInfo struct {
	session *fs

	VState State `json:"state"`

	createdAt   time.Time
	VRemoteUser string   `json:"remoteUser"`
	VRemoteHost net.Host `json:"remoteHost"`

	created fsCreated
}

func (this *fsInfo) init(session *fs) {
	this.session = session
	this.created.init(this)
}

func (this *fsInfo) GetField(name string, ce contextEnabled) (any, bool, error) {
	switch name {
	case "flow":
		return this.Flow(), true, nil
	case "id":
		return this.Id(), true, nil
	case "state":
		return this.State(), true, nil
	case "created":
		v, err := this.Created(ce.Context())
		return v, err == nil, err
	case "lastAccessed":
		v, err := this.LastAccessed(ce.Context())
		return v, err == nil, err
	case "validUntil":
		v, err := this.ValidUntil(ce.Context())
		if err != nil {
			return nil, false, err
		}
		if v.IsZero() {
			return nil, true, nil
		}
		return v, true, err
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

func (this *fsInfo) Flow() configuration.FlowName {
	return this.session.flow
}

func (this *fsInfo) Id() uuid.UUID {
	return this.session.id
}

func (this *fsInfo) State() State {
	return this.VState
}

func (this *fsInfo) String() string {
	return this.session.String()
}

func (this *fsInfo) Created(context.Context) (InfoCreated, error) {
	return &this.created, nil
}

func (this *fsInfo) ValidUntil(ctx context.Context) (result time.Time, _ error) {
	lastAccessed, err := this.LastAccessed(ctx)
	if err != nil {
		return time.Time{}, err
	}
	lat := lastAccessed.At()
	if v := this.session.repository.conf.IdleTimeout.Native(); v > 0 {
		result = lat.Add(v)
	}
	if v := this.session.repository.conf.MaxTimeout.Native(); v > 0 {
		byMax := lat.Add(v)
		if result.IsZero() || byMax.Before(result) {
			result = byMax
		}
	}
	return result, nil
}

func (this *fsInfo) lastAccessed(_ context.Context) (*fsLastAccessed, error) {
	this.session.repository.mutex.RLock()
	defer this.session.repository.mutex.RUnlock()

	f, _, err := this.session.repository.openRead(this.session.flow, this.session.id, FsFileLastAccessed)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseError(f)

	var buf fsLastAccessed
	if err := json.NewDecoder(f).Decode(&buf); err != nil {
		return nil, fmt.Errorf("cannot decode last access of %v: %w", this, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat last access file of %v: %w", this, err)
	}
	buf.at = fi.ModTime()
	buf.init(this)

	return &buf, nil
}

func (this *fsInfo) stat() (os.FileInfo, error) {
	return this.session.repository.stat(this.session.flow, this.session.id, FsFileSession)
}

func (this *fsInfo) LastAccessed(ctx context.Context) (InfoLastAccessed, error) {
	return this.lastAccessed(ctx)
}

func (this *fsInfo) save(_ context.Context) error {
	f, _, err := this.session.repository.openWrite(this.session.flow, this.session.id, FsFileSession, false)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v: %w", this, err)
	}

	if err := os.Chtimes(f.Name(), time.Now(), this.createdAt); err != nil {
		return fmt.Errorf("cannot change time of session %v: %w", this, err)
	}

	return nil
}
