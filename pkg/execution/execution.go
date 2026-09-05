package execution

import "github.com/engity-com/bifroest/pkg/connection"

const (
	EnvName            = "BIFROEST_EXECUTION_ID"
	StateDirectoryName = "executions"
)

type Id = connection.Id

func NewId() (Id, error) {
	return connection.NewId()
}
