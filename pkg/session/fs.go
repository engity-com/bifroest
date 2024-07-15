package session

import (
	"fmt"
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"path/filepath"
	"sync"
)

type FsRepository struct {
	Directory string

	mutex sync.RWMutex
}

func (this *FsRepository) path(flow configuration.FlowName, id uuid.UUID, kind string) (string, error) {
	fs, err := flow.MarshalText()
	if err != nil {
		return "", err
	}
	is, err := id.MarshalText()
	if err != nil {
		return "", err
	}
	return filepath.Join(this.Directory, string(fs), string(is), kind), nil
}

func (this *FsRepository) openRead(flow configuration.FlowName, id uuid.UUID, kind string) (*os.File, error) {
	fn, err := this.path(flow, id, kind)
	if err != nil {
		return nil, err
	}
	return os.Open(fn)
}

func (this *FsRepository) openWrite(flow configuration.FlowName, id uuid.UUID, kind string) (*os.File, error) {
	fn, err := this.path(flow, id, kind)
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Dir(fn), 0700)
	return os.OpenFile(fn, os.O_WRONLY|os.O_TRUNC, 0600)
}

func (this *FsRepository) Create(flow configuration.FlowName, remoteUser string, remoteAddr net.IP) (Session, error) {
	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot create session for user %q@%v at flow %v: %w", remoteUser, remoteAddr, flow, err)
	}

	id, err := uuid.NewUUID()
	if err != nil {
		return fail(err)
	}

	sess := fsSession{
		FsRepository: this,
		flow:         flow,
		id:           id,
	}

	//TODO implement me
	panic("implement me")
}

func (this *FsRepository) Find(name configuration.FlowName, uuid uuid.UUID) (Session, error) {
	//TODO implement me
	panic("implement me")
}

func (this *FsRepository) FindByPublicKey(key ssh.PublicKey) (Session, error) {
	//TODO implement me
	panic("implement me")
}

type fsSession struct {
	*FsRepository
	flow configuration.FlowName
	id   uuid.UUID
}

func (this *fsSession) Info() (Info, error) {

	//TODO implement me
	panic("implement me")
}

func (this *fsSession) PublicKeys(consumer func(key ssh.PublicKey) (canContinue bool, err error)) error {
	//TODO implement me
	panic("implement me")
}

func (this *fsSession) AddPublicKey(key ssh.PublicKey) error {
	//TODO implement me
	panic("implement me")
}

func (this *fsSession) NotifyLastAccess(remoteUser string, remoteAddr net.IP) error {
	//TODO implement me
	panic("implement me")
}
