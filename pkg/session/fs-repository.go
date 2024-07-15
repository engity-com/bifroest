package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FsRepository struct {
	Directory string

	mutex sync.RWMutex
}

func (this *FsRepository) dir(flow configuration.FlowName, id uuid.UUID) (string, error) {
	fs, err := flow.MarshalText()
	if err != nil {
		return "", err
	}
	is, err := id.MarshalText()
	if err != nil {
		return "", err
	}
	return filepath.Join(this.Directory, string(fs), string(is)), nil
}

func (this *FsRepository) file(flow configuration.FlowName, id uuid.UUID, kind string) (string, error) {
	dir, err := this.dir(flow, id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, kind), nil
}

func (this *FsRepository) openRead(flow configuration.FlowName, id uuid.UUID, kind string) (*os.File, string, error) {
	fn, err := this.file(flow, id, kind)
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(fn)
	if err != nil {
		return nil, fn, fmt.Errorf("cannot open session file (%q) of %v/%v for read: %w", fn, flow, id, err)
	}
	return f, fn, nil
}

func (this *FsRepository) openWrite(flow configuration.FlowName, id uuid.UUID, kind string) (*os.File, string, error) {
	fn, err := this.file(flow, id, kind)
	if err != nil {
		return nil, "", err
	}
	_ = os.MkdirAll(filepath.Dir(fn), 0700)
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fn, fmt.Errorf("cannot open session file (%q) of %v/%v for write: %w", fn, flow, id, err)
	}
	return f, fn, nil
}

func (this *FsRepository) Create(flow configuration.FlowName, remoteUser string, remoteAddr net.IP) (Session, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot create session for user %q@%v at flow %v: %w", remoteUser, remoteAddr, flow, err)
	}

	id, err := uuid.NewUUID()
	if err != nil {
		return fail(err)
	}

	sess := fsSession{
		repository:  this,
		VFlow:       flow,
		VId:         id,
		VState:      StateNew,
		VCreatedAt:  time.Now().Truncate(time.Millisecond),
		VRemoteUser: remoteUser,
		VRemoteAddr: remoteAddr,
	}
	if err := sess.save(); err != nil {
		return fail(err)
	}
	if err := sess.NotifyLastAccess(remoteUser, remoteAddr, StateUnchanged); err != nil {
		return fail(err)
	}

	return &sess, nil
}

func (this *FsRepository) FindBy(flow configuration.FlowName, id uuid.UUID) (Session, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	f, _, err := this.openRead(flow, id, FsFileSession)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf := fsSession{
		repository: this,
	}
	if err := json.NewDecoder(f).Decode(&buf); err != nil {
		return nil, fmt.Errorf("cannot decode session %v/%v: %w", flow, id, err)
	}

	return &buf, nil
}

func (this *FsRepository) FindByPublicKey(key ssh.PublicKey) (Session, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	//TODO implement me
	panic("implement me")
}

func (this *FsRepository) DeleteBy(flow configuration.FlowName, id uuid.UUID) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	dir, err := this.dir(flow, id)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("cannot delete session %v/%v: %w", flow, id, err)
	}
	return nil
}

func (this *FsRepository) Delete(s Session) error {
	if s == nil {
		return nil
	}
	switch v := s.(type) {
	case *fsSession:
		return this.DeleteBy(v.VFlow, v.VId)
	default:
		return fmt.Errorf("unknown session type: %T", v)
	}
}
