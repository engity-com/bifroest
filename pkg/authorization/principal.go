package authorization

import (
	"reflect"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

// ErrPrincipalMappingContextUnavailable means a configured mapping has no
// evaluation context. It must not silently fall back to the original principal.
var ErrPrincipalMappingContextUnavailable = errors.System.Newf("principal mapping context is unavailable")

// PrincipalMappingContext exposes the original request's template fields and
// context. Implementations must expose the supplied, unmapped identity as
// "authentication" without recursively resolving its principal. The concrete
// context must retain any additional capabilities used by authorization fields,
// such as platform-specific local-account management information.
type PrincipalMappingContext interface {
	ContextEnabled
	GetField(string) (any, bool, error)
}

// AuthenticationWithPrincipal resolves the verified identity and applies the
// selected flow's configured principal mapping using the production template
// implementation. The mapping changes only Principal, never Issuer or Subject.
//
// contextFor is called only when a mapping is needed. It returns the concrete
// request context with the original identity bound to "authentication"; no generic
// wrapper is added that could discard optional context capabilities. This allows
// service and controlled policy evaluations to share the mapping semantics without
// initializing a service, authorizer, account repository or session repository.
// Template functions and context getters still use the caller's dependencies;
// this function alone does not make their execution hermetic or side-effect-free.
func AuthenticationWithPrincipal(auth Authorization, flows configuration.Flows, contextFor func(authentication.Identity) PrincipalMappingContext) (authentication.Identity, error) {
	identity, err := AuthenticationOf(auth)
	if err != nil {
		return authentication.Identity{}, errors.System.Newf("%w", err)
	}
	if auth == nil {
		return identity, nil
	}
	for _, flow := range flows {
		if flow.Name != auth.Flow() || flow.Authorization.Principal.IsZero() {
			continue
		}
		if !identity.IsAuthenticated() {
			return authentication.Identity{}, errors.Config.Newf("cannot map an anonymous authentication principal")
		}
		if contextFor == nil {
			return authentication.Identity{}, ErrPrincipalMappingContextUnavailable
		}
		mappingContext := contextFor(identity)
		if isNilPrincipalMappingContext(mappingContext) {
			return authentication.Identity{}, ErrPrincipalMappingContextUnavailable
		}
		principal, err := flow.Authorization.Principal.Render(mappingContext)
		if err != nil {
			return authentication.Identity{}, errors.Config.Newf("cannot resolve authentication principal: %w", err)
		}
		identity.Principal = principal
		if err := identity.Validate(); err != nil {
			return authentication.Identity{}, errors.Config.Newf("%w", err)
		}
		return identity, nil
	}
	return identity, nil
}

func isNilPrincipalMappingContext(value PrincipalMappingContext) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
