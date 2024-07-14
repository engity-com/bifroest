package authorization

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"github.com/engity-com/yasshd/pkg/user"
)

type Local struct {
	*user.User
	flow configuration.FlowName
}

func (this *Local) IsAuthorized() bool {
	return true
}

func (this *Local) Flow() configuration.FlowName {
	return this.flow
}
