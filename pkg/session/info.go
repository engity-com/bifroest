package session

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
)

type Info interface {
	Flow() configuration.FlowName
	Id() uuid.UUID
	State() State
	Created(context.Context) (InfoCreated, error)
	LastAccessed(context.Context) (InfoLastAccessed, error)
	// ValidUntil defines until when the actual Session is valid to be used.
	// If returned time.Time.IsZero() means forever.
	ValidUntil(context.Context) (time.Time, error)
	String() string
}

type InfoCreated interface {
	At() time.Time
	Remote() net.Remote
}

type InfoLastAccessed interface {
	At() time.Time
	Remote() net.Remote
}
