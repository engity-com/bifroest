package authorization

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
)

// AuthenticatedSessionResolver is an optional trusted adapter hook. Built-in
// authorizers call it only after primary credentials/possession were verified.
// It is not called for unsigned key probes or anonymous identity-based reuse.
// handled=false preserves adapters/repositories without association support.
type AuthenticatedSessionResolver interface {
	ResolveAuthenticatedSession(Authorization, []byte) (found session.Session, handled bool, err error)
}

func resolveAuthenticatedSession(req Request, auth Authorization, token []byte) (session.Session, bool, error) {
	if resolver, ok := req.(AuthenticatedSessionResolver); ok {
		found, handled, err := resolver.ResolveAuthenticatedSession(auth, token)
		if err != nil {
			return nil, handled, err
		}
		if handled && (found == nil || found.Flow() != auth.Flow()) {
			return nil, true, fmt.Errorf("authenticated session resolver returned an invalid session")
		}
		return found, handled, nil
	}
	return nil, false, nil
}
