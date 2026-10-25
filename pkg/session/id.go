package session

import (
	"github.com/engity-com/bifroest/pkg/common"
	sessionid "github.com/engity-com/bifroest/pkg/session/id"
)

type Id = sessionid.Id

func NewId() (Id, error) { return sessionid.NewId() }
func MustNewId() Id      { id, err := NewId(); common.Must(err); return id }
