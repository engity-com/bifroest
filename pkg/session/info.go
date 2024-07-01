package session

import (
	"context"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"time"
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
	Remote() common.Remote
}

type InfoLastAccessed interface {
	At() time.Time
	Remote() common.Remote
}
