package session

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/google/uuid"
	"net"
	"time"
)

type Info struct {
	Flow         configuration.FlowName `json:"flow,omitempty"`
	Id           uuid.UUID              `json:"id"`
	State        State                  `json:"state,omitempty"`
	Created      InfoCreated            `json:"created,omitempty"`
	LastAccessed InfoLastAccessed       `json:"lastAccessed,omitempty"`
}

type InfoCreated struct {
	At         time.Time `json:"at"`
	RemoteUser string    `json:"remoteUser,omitempty"`
	RemoteAddr net.IP    `json:"remoteAddr,omitempty"`
}

type InfoLastAccessed struct {
	At         time.Time `json:"at"`
	RemoteUser string    `json:"remoteUser,omitempty"`
	RemoteAddr net.IP    `json:"remoteAddr,omitempty"`
}
