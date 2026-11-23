package service

import (
	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
)

func (this *environmentContext) Authentication() (authentication.Identity, error) {
	if this.service == nil || this.service.Service == nil || this.authorization == nil {
		return authorization.AuthenticationOf(this.authorization)
	}
	return authorization.AuthenticationWithPrincipal(this.authorization, this.service.Configuration.Flows, func(identity authentication.Identity) authorization.PrincipalMappingContext {
		// A mapping may refer to the default principal without recursively
		// evaluating itself. All other fields retain their original context,
		// including platform-specific local-account management helpers.
		return &principalMappingContext{environmentContext: this, identity: identity}
	})
}

type principalMappingContext struct {
	*environmentContext
	identity authentication.Identity
}

func (this *principalMappingContext) GetField(name string) (any, bool, error) {
	if name == "authentication" {
		return this.identity, true, nil
	}
	return this.environmentContext.GetField(name)
}
