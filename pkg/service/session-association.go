package service

import (
	"bytes"
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

func (this *authorizeRequest) ResolveAuthenticatedSession(auth authorization.Authorization, token []byte) (session.Session, bool, error) {
	return this.service.resolveAuthenticatedSession(&environmentContext{service: this.service, connection: this.connection, authorization: auth}, token)
}

func (this *authorizeRequest) ResolveAuthenticatedSessionWithReuse(auth authorization.Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	if reuse == nil {
		return nil, true, fmt.Errorf("session association requires a credential reuse check")
	}
	return this.service.resolveAuthenticatedSessionWithReuse(&environmentContext{service: this.service, connection: this.connection, authorization: auth}, token, reuse)
}

func (this *authorizeRequest) ResolveAuthenticatedSessionWithReuseContext(ctx context.Context, auth authorization.Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	base := &environmentContext{service: this.service, connection: this.connection, authorization: auth}
	return this.service.resolveAuthenticatedSessionWithReuse(&associationCandidateContext{associationBaseContext: base, ctx: ctx, auth: auth}, token, reuse)
}

func (this *publicKeyAuthorizeRequest) ResolveAuthenticatedSession(auth authorization.Authorization, token []byte) (session.Session, bool, error) {
	if !this.verified {
		return nil, true, fmt.Errorf("session association requires verified key possession")
	}
	return this.authorizeRequest.ResolveAuthenticatedSession(auth, token)
}

func (this *publicKeyAuthorizeRequest) ResolveAuthenticatedSessionWithReuse(auth authorization.Authorization, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	if !this.verified {
		return nil, true, fmt.Errorf("session association requires verified key possession")
	}
	return this.authorizeRequest.ResolveAuthenticatedSessionWithReuse(auth, token, reuse)
}

// resolveAuthenticatedSession is transport-neutral. It accepts only a trusted
// post-credential authorization/context, not HTTP payload identities or probes.
// Static authorizers use opaque token equality. Rotating authorizers supply a
// trusted, lock-coordinated check through resolveAuthenticatedSessionWithReuse.
func (this *service) resolveAuthenticatedSession(base environment.Context, token []byte) (session.Session, bool, error) {
	return this.resolveAuthenticatedSessionWithReuse(base, token, func(ctx context.Context, candidate session.Session) (bool, error) {
		stored, err := candidate.AuthorizationToken(ctx)
		return err == nil && bytes.Equal(stored, token), err
	})
}

func (this *service) resolveAuthenticatedSessionWithReuse(base environment.Context, token []byte, reuse session.Predicate) (session.Session, bool, error) {
	if reuse == nil {
		return nil, true, fmt.Errorf("session association requires a credential reuse check")
	}
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
	if this.runtime != nil && !this.runtime.allowFlow(this.generation, auth.Flow()) {
		return nil, true, fmt.Errorf("authenticated session flow has been removed")
	}
	release, err := this.retainRuntime()
	if err != nil {
		return nil, true, err
	}
	defer release()
	found, created, err := repository.ResolveAssociatedSession(this.runtimeCreationContext(base.Context(), auth.Flow()), session.AssociationRequest{
		Flow: auth.Flow(), Identity: identity, Remote: base.Connection().Remote(), AuthorizationToken: token,
		ResolveTarget: func(ctx context.Context, ref session.Reference) (session.Target, error) {
			return this.resolveSessionTarget(newAssociationTargetContext(ctx, base, ref), ref, resolver)
		},
		Eligible: func(_ context.Context, candidate session.Session) (bool, error) {
			return this.loginSessionCompatible(candidate), nil
		},
		Compatible: func(ctx context.Context, candidate session.Session) (bool, error) {
			if !this.loginSessionCompatible(candidate) {
				return false, nil
			}
			if compatible, err := this.associationEnvironmentCompatible(ctx, base, candidate); err != nil || !compatible {
				return compatible, err
			}
			return reuse(ctx, candidate)
		},
	})
	if err == nil {
		if found == nil {
			return nil, true, fmt.Errorf("session association returned no session")
		}
		if err := this.bindAssociatedRuntimeSession(base.Context(), found, created); err != nil {
			return nil, true, err
		}
	}
	return found, true, err
}

func (this *service) resolveSessionTarget(ctx environment.Context, ref session.Reference, fallback environment.SessionTargetResolver) (session.Target, error) {
	if this.resources == nil || this.Watch != configuration.WatchModeReuse {
		return fallback.ResolveSessionTarget(ctx)
	}
	owner, release, err := this.resources.retainSessionOwner(sessionConnectionKey{flow: ref.Flow, id: ref.Id})
	if err != nil {
		// New/unowned sessions always use today's complete target definition.
		return fallback.ResolveSessionTarget(ctx)
	}
	defer release()
	if owner != this {
		if resolver, ok := environment.SessionReuseTargetResolverFor(this.environments, ref.Flow); ok {
			for _, flow := range owner.Configuration.Flows {
				if flow.Name == ref.Flow {
					return resolver.ResolveSessionReuseTarget(ctx, flow.Environment)
				}
			}
		}
	}
	return fallback.ResolveSessionTarget(ctx)
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
func (this *associationCandidateContext) TemplateEvaluationParent() any {
	return this.associationBaseContext
}
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
func (this *associationTargetContext) TemplateEvaluationParent() any {
	return this.associationBaseContext
}
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
	if name == "connection" {
		view, err := bconn.TemplateViewOf(base)
		return view, true, err
	}
	if provider, ok := base.(interface {
		GetField(string) (any, bool, error)
	}); ok {
		return provider.GetField(name)
	}
	switch name {
	case "remote":
		return base.Connection().Remote(), true, nil
	default:
		return nil, false, fmt.Errorf("session target template context field unavailable")
	}
}
