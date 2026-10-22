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

// AuthenticatedSessionReuseResolver supports authorizer-owned checks for rotating
// credentials/evidence. The trusted check runs only for an already bound, valid,
// same-subject/same-target candidate under serialized association selection. It
// must coordinate with the authorizer's credential locks and must never overwrite
// live refresh state with the newly presented login token. A missing capability
// preserves the previous allocation path rather than guessing token semantics.
type AuthenticatedSessionReuseResolver interface {
	ResolveAuthenticatedSessionWithReuse(Authorization, []byte, session.Predicate) (session.Session, bool, error)
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

func resolveAuthenticatedSessionWithReuse(req Request, auth Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	resolver, ok := req.(AuthenticatedSessionReuseResolver)
	if !ok {
		return nil, false, nil
	}
	if reuse == nil {
		return nil, true, fmt.Errorf("authenticated session reuse requires a credential check")
	}
	found, handled, err := resolver.ResolveAuthenticatedSessionWithReuse(auth, token, reuse)
	if err != nil {
		return nil, handled, err
	}
	if handled && (found == nil || found.Flow() != auth.Flow()) {
		return nil, true, fmt.Errorf("authenticated session resolver returned an invalid session")
	}
	return found, handled, nil
}
