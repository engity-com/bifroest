package session

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"net"
)

type Repository interface {
	Create(flow configuration.FlowName, remoteUser string, remoteAddr net.IP) (Session, error)

	FindBy(configuration.FlowName, uuid.UUID) (Session, error)
	FindByPublicKey(ssh.PublicKey) (Session, error)

	DeleteBy(configuration.FlowName, uuid.UUID) error
	Delete(Session) error
}
