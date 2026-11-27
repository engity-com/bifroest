package service

import (
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
)

// Register existing ownership before starting housekeeping/refresh or admitting
// connections. Unknown/corrupt flows remain preserved for operator inspection.
func (this *service) registerRuntimeSessions(ctx context.Context) error {
	return this.sessions.FindAll(ctx, func(ctx context.Context, sess session.Session) (bool, error) {
		if !this.runtime.allowFlow(this.generation, sess.Flow()) {
			return true, nil
		}
		if this.runtime.persistence != nil {
			provider, ok := sess.(session.RuntimeOwnershipSession)
			if !ok {
				return true, nil
			}
			owner, err := provider.RuntimeOwnership(ctx)
			if err != nil || owner == nil || !owner.Matches(this.generation.ownership.Flows[sess.Flow()]) {
				this.logger().With("flow", sess.Flow()).With("sessionId", sess.Id()).Warn("session has no matching persistent owner; access discarded, backend state preserved")
				return true, nil
			}
			revoked, err := provider.RuntimeRevoked(ctx)
			if err != nil {
				this.logger().With("flow", sess.Flow()).With("sessionId", sess.Id()).WithError(err).Warn("cannot verify persistent revocation; preserving session without access")
				return true, nil
			}
			if err := this.runtime.bindSession(this.generation, sess, true); err != nil {
				return false, err
			}
			if revoked {
				this.runtime.revokeSession(sess.Flow(), sess.Id())
			}
		} else if err := this.runtime.bindSession(this.generation, sess, false); err != nil {
			return false, err
		}
		return true, nil
	}, &session.FindOpts{
		DiagnosticConsumer: func(_ context.Context, diagnostic session.FindDiagnostic) error {
			this.logger().With("flow", diagnostic.Flow).With("sessionId", diagnostic.Id).
				WithError(diagnostic.Err).Warn("cannot register runtime ownership of session; preserving it")
			return nil
		},
	})
}

func (this *service) retainRuntime() (func(), error) {
	if this.runtime == nil {
		return func() {}, nil
	}
	return this.runtime.retain(this.generation)
}

func (this *service) bindAssociatedRuntimeSession(ctx context.Context, sess session.Session, created bool) error {
	if this.runtime == nil {
		return nil
	}
	if err := this.runtime.bindSession(this.generation, sess, created); err != nil {
		if created {
			_, disposeErr := sess.Dispose(ctx)
			if disposeErr != nil {
				return fmt.Errorf("%w; cannot dispose rejected new session: %w", err, disposeErr)
			}
		}
		return err
	}
	return nil
}
