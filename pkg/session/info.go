package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/google/uuid"
	"time"
)

type Info interface {
	Flow() configuration.FlowName
	Id() uuid.UUID
	State() State
	Created() (InfoCreated, error)
	LastAccessed() (InfoLastAccessed, error)
	ValidUntil() (time.Time, error)
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
