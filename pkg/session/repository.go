package session

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"net"
)

type Repository interface {
	Create(flow configuration.FlowName, remoteUser string, remoteAddr net.IP) (Session, error)
	Find(configuration.FlowName, uuid.UUID) (Session, error)
	FindByPublicKey(ssh.PublicKey) (Session, error)
}
