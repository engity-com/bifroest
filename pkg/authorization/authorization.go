package authorization

import "github.com/engity-com/yasshd/pkg/configuration"

type Authorization interface {
	IsAuthorized() bool
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

func (this *forbiddenResponse) Flow() configuration.FlowName {
	return ""
}
