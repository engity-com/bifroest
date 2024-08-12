package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"time"
)

func NewSimpleRepository(conf *configuration.SessionSimple) (*SimpleRepository, error) {
	result := SimpleRepository{
		conf: conf,
	}

	return &result, nil
}

type SimpleRepository struct {
	conf *configuration.SessionSimple
}

func (this *SimpleRepository) Create(flow configuration.FlowName, remote common.Remote, _ []byte) (Session, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &simple{
		flow:           flow,
		id:             id,
		state:          StateNew,
		createdAt:      now,
		createdBy:      remote,
		lastAccessedAt: now,
		lastAccessedBy: remote,
	}, nil
}

func (this *SimpleRepository) FindBy(configuration.FlowName, uuid.UUID) (Session, error) {
	return nil, ErrNoSuchSession
}

func (this *SimpleRepository) FindByPublicKey(ssh.PublicKey, func(Session) (bool, error)) (Session, error) {
	return nil, ErrNoSuchSession
}

func (this *SimpleRepository) DeleteBy(configuration.FlowName, uuid.UUID) error {
	return nil
}

func (this *SimpleRepository) Delete(Session) error {
	return nil
}

func (this *SimpleRepository) Close() error {
	return nil
}
