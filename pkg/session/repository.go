package session

import (
	"errors"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"io"
)

var (
	ErrNoSuchSession = errors.New("no such session")
)

type Repository interface {
	Create(flow configuration.FlowName, remote common.Remote, authToken []byte) (Session, error)

	FindBy(configuration.FlowName, uuid.UUID) (Session, error)
	FindByPublicKey(key ssh.PublicKey, predicate func(Session) (bool, error)) (Session, error)

	DeleteBy(configuration.FlowName, uuid.UUID) error
	Delete(Session) error
}

type CloseableRepository interface {
	Repository
	io.Closer
}
