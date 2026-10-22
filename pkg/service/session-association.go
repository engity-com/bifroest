package service

import (
	"bytes"
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *authorizeRequest) ResolveAuthenticatedSession(auth authorization.Authorization, token []byte) (session.Session, bool, error) {
	return this.service.resolveAuthenticatedSession(&environmentContext{service: this.service, connection: this.connection, authorization: auth}, token)
}

func (this *publicKeyAuthorizeRequest) ResolveAuthenticatedSession(auth authorization.Authorization, token []byte) (session.Session, bool, error) {
	if !this.verified {
		return nil, true, fmt.Errorf("session association requires verified key possession")
	}
	return this.authorizeRequest.ResolveAuthenticatedSession(auth, token)
}

// resolveAuthenticatedSession is transport-neutral. It accepts only a trusted
// post-credential authorization/context, not HTTP payload identities or probes.
// Fresh OIDC grants deliberately do not call this hook until refresh coordination
// is implemented; token comparison is for static authorizers only.
func (this *service) resolveAuthenticatedSession(base environment.Context, token []byte) (session.Session, bool, error) {
	auth := base.Authorization()
	if auth == nil || !auth.IsAuthorized() {
		return nil, true, fmt.Errorf("session association requires an authenticated authorization")
	}
	resolver, ok := environment.SessionTargetResolverFor(this.environments, auth.Flow())
	if !ok {
		return nil, false, nil
	}
	repository, ok := this.sessions.(session.AssociatedRepository)
	if !ok {
		return nil, false, nil
	}
	identity, err := authorization.AuthenticationOf(auth)
	if err != nil {
		return nil, true, err
	}
	if !identity.IsAuthenticated() {
		return nil, false, nil
	}
	if len(token) == 0 {
		return nil, true, fmt.Errorf("authenticated session association requires credentials")
	}
	found, _, err := repository.ResolveAssociatedSession(base.Context(), session.AssociationRequest{
		Flow: auth.Flow(), Identity: identity, Remote: base.Connection().Remote(), AuthorizationToken: token,
		ResolveTarget: func(ctx context.Context, ref session.Reference) (session.Target, error) {
			return resolver.ResolveSessionTarget(newAssociationTargetContext(ctx, base, ref))
		},
		Compatible: func(ctx context.Context, candidate session.Session) (bool, error) {
			stored, err := candidate.AuthorizationToken(ctx)
			if err != nil {
				return false, err
			}
			if !bytes.Equal(stored, token) {
				return false, nil
			}
			return this.associationEnvironmentCompatible(ctx, base, candidate)
		},
	})
	return found, true, err
}

func (this *service) associationEnvironmentCompatible(ctx context.Context, base environment.Context, candidate session.Session) (bool, error) {
	// A bound, matching primary login can join before environment provisioning.
	// There is no persisted environment credential to restore/compare yet. Ensure
	// still owns provisioning locks and all execution-time credential checks.
	raw, err := candidate.EnvironmentToken(ctx)
	if err != nil {
		return false, err
	}
	if len(raw) == 0 {
		return true, nil
	}
	if checker, ok := this.environments.(environment.ContextualSessionCompatibilityChecker); ok {
		return checker.IsSessionCompatibleWith(&associationCandidateContext{associationBaseContext: base, ctx: ctx, auth: &sessionCompatibilityAuthorization{Authorization: base.Authorization(), session: candidate, fieldContext: base}, session: candidate}, candidate)
	}
	if checker, ok := this.environments.(environment.SessionCompatibilityChecker); ok {
		return checker.IsSessionCompatible(ctx, candidate)
	}
	return true, nil
}

type associationCandidateContext struct {
	associationBaseContext
	ctx     context.Context
	auth    authorization.Authorization
	session session.Session
}

func (this *associationCandidateContext) Context() context.Context { return this.ctx }
func (this *associationCandidateContext) Authorization() authorization.Authorization {
	return this.auth
}
func (this *associationCandidateContext) GetField(name string) (any, bool, error) {
	switch name {
	case "context":
		return this.ctx, true, nil
	case "authorization":
		return this.auth, true, nil
	case "session":
		return this.session, true, nil
	default:
		return associationBaseField(this.associationBaseContext, name)
	}
}

// Target templates can use the prospective flow/ID without creating a durable
// placeholder session. Immutable creation metadata comes from the repository;
// mutable session fields cannot define persistent target ownership.
type associationTargetContext struct {
	associationBaseContext
	ctx       context.Context
	reference associationTargetReference
	auth      *associationTargetAuthorization
}
type associationTargetReference struct{ session.Reference }

func (this associationTargetReference) GetField(name string) (any, bool, error) {
	switch name {
	case "id":
		return this.Id, true, nil
	case "flow":
		return this.Flow, true, nil
	case "created":
		if this.Created != nil {
			return this.Created, true, nil
		}
		return nil, false, fmt.Errorf("session target creation metadata unavailable")
	default:
		return nil, false, fmt.Errorf("session target templates support only immutable session fields")
	}
}
func newAssociationTargetContext(ctx context.Context, base environment.Context, ref session.Reference) *associationTargetContext {
	reference := associationTargetReference{ref}
	return &associationTargetContext{associationBaseContext: base, ctx: ctx, reference: reference, auth: &associationTargetAuthorization{sessionCompatibilityAuthorization: sessionCompatibilityAuthorization{Authorization: base.Authorization(), fieldContext: base}, reference: reference}}
}
func (this *associationTargetContext) Context() context.Context                   { return this.ctx }
func (this *associationTargetContext) Authorization() authorization.Authorization { return this.auth }
func (this *associationTargetContext) GetField(name string) (any, bool, error) {
	switch name {
	case "context":
		return this.ctx, true, nil
	case "authorization":
		return this.auth, true, nil
	case "session":
		return this.reference, true, nil
	default:
		return associationBaseField(this.associationBaseContext, name)
	}
}

type associationTargetAuthorization struct {
	sessionCompatibilityAuthorization
	reference associationTargetReference
}

func (this *associationTargetAuthorization) GetField(name string, ctx authorization.ContextEnabled) (any, bool, error) {
	if name == "session" {
		return this.reference, true, nil
	}
	return this.sessionCompatibilityAuthorization.GetField(name, ctx)
}

type associationBaseContext interface{ environment.Context }

func associationBaseField(base environment.Context, name string) (any, bool, error) {
	if provider, ok := base.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return provider.GetField(name)
	}
	switch name {
	case "remote":
		return base.Connection().Remote(), true, nil
	case "connection":
		return base.Connection(), true, nil
	default:
		return nil, false, fmt.Errorf("session target template context field unavailable")
	}
}
