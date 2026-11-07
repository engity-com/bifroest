package service

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

type compatibleSessionRepository struct {
	session.Repository
	environments     environment.CloseableRepository
	authorizeRequest *authorizeRequest
}

func (this *compatibleSessionRepository) FindBy(ctx context.Context, flow configuration.FlowName, id session.Id, opts *session.FindOpts) (session.Session, error) {
	return this.Repository.FindBy(ctx, flow, id, this.withCompatibility(opts))
}

func (this *compatibleSessionRepository) FindByPublicKey(ctx context.Context, key ssh.PublicKey, opts *session.FindOpts) (session.Session, error) {
	return this.Repository.FindByPublicKey(ctx, key, this.withCompatibility(opts))
}

func (this *compatibleSessionRepository) FindByAccessToken(ctx context.Context, token []byte, opts *session.FindOpts) (session.Session, error) {
	return this.Repository.FindByAccessToken(ctx, token, this.withCompatibility(opts))
}

func (this *compatibleSessionRepository) withCompatibility(opts *session.FindOpts) *session.FindOpts {
	result := &session.FindOpts{}
	if opts != nil {
		*result = *opts
		result.Predicates = append(session.Predicates(nil), opts.Predicates...)
	}
	result.Predicates = append(result.Predicates, func(ctx context.Context, candidate session.Session) (bool, error) {
		if auth := this.authorizeRequest.authorization; auth != nil {
			checker, ok := this.environments.(environment.ContextualSessionCompatibilityChecker)
			if ok {
				candidateAuth := &sessionCompatibilityAuthorization{Authorization: auth, session: candidate}
				templateContext := &sessionCompatibilityEnvironmentContext{
					environmentContext: environmentContext{
						service:       this.authorizeRequest.service,
						connection:    this.authorizeRequest.connection,
						authorization: candidateAuth,
					},
					session: candidate,
				}
				return checker.IsSessionCompatibleWith(templateContext, candidate)
			}
		}
		checker, ok := this.environments.(environment.SessionCompatibilityChecker)
		if !ok {
			return true, nil
		}
		return checker.IsSessionCompatible(ctx, candidate)
	})
	result.Predicates = append(result.Predicates, this.associationCompatible)
	return result
}

// A remembered key or legacy token lookup must not bypass an existing immutable
// association. Unbound legacy sessions retain their independent proof-based path.
func (this *compatibleSessionRepository) associationCompatible(ctx context.Context, candidate session.Session) (bool, error) {
	association, err := session.AssociationOf(ctx, candidate)
	if errors.Is(err, session.ErrAssociationUnavailable) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if association == nil {
		return true, nil
	}
	auth := this.authorizeRequest.authorization
	if auth == nil {
		return true, nil
	} // Unsigned OIDC probe: checked again after proof.
	identity, err := authorization.AuthenticationOf(auth)
	if err != nil {
		return false, err
	}
	if auth.Flow() != candidate.Flow() || !association.SameSubject(identity) {
		return false, nil
	}
	stored, err := candidate.AuthorizationToken(ctx)
	if err != nil {
		return false, err
	}
	if len(stored) == 0 {
		return false, nil
	}
	resolver, ok := environment.SessionTargetResolverFor(this.environments, auth.Flow())
	if !ok {
		return false, nil
	}
	base := &environmentContext{service: this.authorizeRequest.service, connection: this.authorizeRequest.connection, authorization: auth, executionContext: ctx}
	info, err := candidate.Info(ctx)
	if err != nil {
		return false, err
	}
	created, err := info.Created(ctx)
	if err != nil {
		return false, err
	}
	target, err := resolver.ResolveSessionTarget(newAssociationTargetContext(ctx, base, session.Reference{Flow: candidate.Flow(), Id: candidate.Id(), Created: created}))
	return err == nil && target == association.Target, err
}

type sessionCompatibilityAuthorization struct {
	authorization.Authorization
	session      session.Session
	fieldContext authorization.ContextEnabled
}

func (this *sessionCompatibilityAuthorization) FindSession() session.Session {
	return this.session
}

func (this *sessionCompatibilityAuthorization) AuthorizationKind() string {
	return authorization.KindOf(this.Authorization)
}

func (this *sessionCompatibilityAuthorization) Authentication() (authentication.Identity, error) {
	return authorization.AuthenticationOf(this.Authorization)
}

func (this *sessionCompatibilityAuthorization) AuthorizedKeyPolicy() *authorization.AuthorizedKeyPolicy {
	return authorization.AuthorizedKeyPolicyOf(this.Authorization)
}

func (this *sessionCompatibilityAuthorization) AuthorizationEvidence() *authorization.AuthorizationEvidence {
	return authorization.AuthorizationEvidenceOf(this.Authorization)
}

func (this *sessionCompatibilityAuthorization) GetField(name string, ctx authorization.ContextEnabled) (any, bool, error) {
	if name == "session" {
		info, err := this.session.Info(ctx.Context())
		return info, true, err
	}
	provider, ok := this.Authorization.(interface {
		GetField(string, authorization.ContextEnabled) (any, bool, error)
	})
	if !ok {
		return nil, false, nil
	}
	if this.fieldContext != nil {
		ctx = this.fieldContext
	}
	return provider.GetField(name, ctx)
}

type sessionCompatibilityEnvironmentContext struct {
	environmentContext
	session session.Session
}

func (this *sessionCompatibilityEnvironmentContext) GetField(name string) (any, bool, error) {
	if name == "session" {
		return this.session, true, nil
	}
	return this.environmentContext.GetField(name)
}
