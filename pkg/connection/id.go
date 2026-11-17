package connection

import (
	"github.com/engity-com/bifroest/pkg/common"
	connectionid "github.com/engity-com/bifroest/pkg/connection/id"
)

type Id = connectionid.Id

func NewId() (Id, error) { return connectionid.NewId() }
func MustNewId() Id      { id, err := NewId(); common.Must(err); return id }
