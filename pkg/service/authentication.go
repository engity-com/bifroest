package service

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
)

func (this *environmentContext) Authentication() (authentication.Identity, error) {
	identity, err := authorization.AuthenticationOf(this.authorization)
	if err != nil {
		return authentication.Identity{}, err
	}
	if this.service == nil || this.service.Service == nil || this.authorization == nil {
		return identity, nil
	}
	for _, flow := range this.service.Configuration.Flows {
		if flow.Name != this.authorization.Flow() || flow.Authorization.Principal.IsZero() {
			continue
		}
		if !identity.IsAuthenticated() {
			return authentication.Identity{}, fmt.Errorf("cannot map an anonymous authentication principal")
		}
		// A mapping may refer to the default principal without recursively
		// evaluating itself. All other fields retain their original context,
		// including platform-specific local-account management helpers.
		mappingContext := principalMappingContext{environmentContext: this, identity: identity}
		principal, err := flow.Authorization.Principal.Render(&mappingContext)
		if err != nil {
			return authentication.Identity{}, fmt.Errorf("cannot resolve authentication principal: %w", err)
		}
		identity.Principal = principal
		if err := identity.Validate(); err != nil {
			return authentication.Identity{}, err
		}
		return identity, nil
	}
	return identity, nil
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
