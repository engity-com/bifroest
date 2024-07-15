package session

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/google/uuid"
	"net"
	"time"
)

type Info interface {
	Flow() configuration.FlowName
	Id() uuid.UUID
	State() State
	Created() (InfoCreated, error)
	LastAccessed() (InfoLastAccessed, error)
}

type InfoCreated interface {
	At() time.Time
	RemoteUser() string
	RemoteAddr() net.IP
}

type InfoLastAccessed interface {
	At() time.Time
	RemoteUser() string
	RemoteAddr() net.IP
}
