package authorization

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/engity-com/yasshd/pkg/sys"
	"github.com/engity-com/yasshd/pkg/user"
)

type Local struct {
	*user.User
	envVars sys.EnvVars
	flow    configuration.FlowName
}

func (this *Local) IsAuthorized() bool {
	return true
}

func (this *Local) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *Local) Flow() configuration.FlowName {
	return this.flow
}
