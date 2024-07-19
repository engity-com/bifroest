package authorization

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Authorization interface {
	IsAuthorized() bool
	EnvVars() sys.EnvVars
	Flow() configuration.FlowName
}

func Forbidden() Authorization {
	return &forbiddenI
}

type forbiddenResponse struct{}

var forbiddenI = forbiddenResponse{}

func (this *forbiddenResponse) IsAuthorized() bool {
	return false
}

func (this *forbiddenResponse) EnvVars() sys.EnvVars {
	return nil
}

func (this *forbiddenResponse) Flow() configuration.FlowName {
	return ""
}
