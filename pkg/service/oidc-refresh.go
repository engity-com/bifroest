package service

import (
	"context"
	goerrors "errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

const (
	oidcRefreshConcurrency  = 8
	oidcRefreshTimeout      = 15 * time.Second
	oidcRefreshRetry        = time.Minute
	oidcRefreshUnknownGrace = time.Second
)

// oidcRefreshManager owns refresh workers for persisted sessions, independently
// of the SSH connections or individual session objects that discovered them.
type oidcRefreshManager struct {
	service       *service
	ctx           context.Context
	cancel        context.CancelFunc
	mutex         sync.Mutex
	workers       map[sessionConnectionKey]context.CancelFunc
	deadlines     map[sessionConnectionKey]chan time.Time
	lastDeadlines map[sessionConnectionKey]time.Time
	invalidating  map[sessionConnectionKey]struct{}
	authorizers   map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer
	limit         chan struct{}
	done          sync.WaitGroup
}

func (this *oidcRefreshManager) init(svc *service) error {
	facade, ok := svc.authorizer.(*authorization.AuthorizerFacade)
	if !ok {
		return nil
	}
	authorizers := make(map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer)
	for _, flow := range svc.Configuration.Flows {
		conf, ok := flow.Authorization.V.(*configuration.AuthorizationOidcDeviceAuth)
		if !ok || !conf.RefreshEnabled() {
			continue
		}
		if authorizer := facade.OidcRefreshAuthorizer(flow.Name); authorizer != nil {
			authorizers[flow.Name] = authorizer
		}
	}
	if len(authorizers) == 0 {
		return nil
	}
	this.service = svc
	this.authorizers = authorizers
	this.workers = make(map[sessionConnectionKey]context.CancelFunc)
	this.deadlines = make(map[sessionConnectionKey]chan time.Time)
	this.lastDeadlines = make(map[sessionConnectionKey]time.Time)
	this.invalidating = make(map[sessionConnectionKey]struct{})
	this.limit = make(chan struct{}, oidcRefreshConcurrency)
	this.ctx, this.cancel = context.WithCancel(context.Background())
	for _, authorizer := range authorizers {
		authorizer.OnVerified = this.verificationUpdated
		authorizer.OnLostAccess = this.invalidateSession
	}
	if err := svc.sessions.FindAll(this.ctx, func(_ context.Context, sess session.Session) (bool, error) {
		this.register(sess)
		return true, nil
	}, &session.FindOpts{
		DiagnosticConsumer: func(_ context.Context, diagnostic session.FindDiagnostic) error {
			svc.logger().With("flow", diagnostic.Flow).With("sessionId", diagnostic.Id).
				WithError(diagnostic.Err).Warn("cannot inspect session for OIDC refresh; preserving it")
			return nil
		},
	}); err != nil {
		_ = this.Close()
		return fmt.Errorf("cannot discover OIDC refresh sessions: %w", err)
	}
	return nil
}

func (this *oidcRefreshManager) register(sess session.Session) {
	if this.ctx == nil || this.ctx.Err() != nil || sess == nil || this.authorizers[sess.Flow()] == nil {
		return
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.ctx.Err() != nil || this.workers[key] != nil {
		return
	}
	ctx, cancel := context.WithCancel(this.ctx)
	if this.failClosed(key.flow) {
		if this.deadlines == nil {
			this.deadlines = make(map[sessionConnectionKey]chan time.Time)
		}
		this.deadlines[key] = make(chan time.Time, 1)
	}
	this.workers[key] = cancel
	this.done.Add(1)
	go this.run(ctx, key)
}

func (this *oidcRefreshManager) stop(sess session.Session) {
	if sess == nil || this.ctx == nil {
		return
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	if cancel := this.workers[key]; cancel != nil {
		cancel()
	}
	this.mutex.Unlock()
}

func (this *oidcRefreshManager) run(ctx context.Context, key sessionConnectionKey) {
	defer this.done.Done()
	defer func() {
		this.mutex.Lock()
		delete(this.workers, key)
		delete(this.deadlines, key)
		delete(this.lastDeadlines, key)
		this.mutex.Unlock()
	}()
	logger := this.service.logger().With("flow", key.flow).With("sessionId", key.id)
	authorizer := this.authorizers[key.flow]
	// A deadline read or provider call can block behind another worker. The
	// watchdog therefore owns its timer independently of the refresh loop.
	if this.failClosed(key.flow) {
		this.mutex.Lock()
		deadlines := this.deadlines[key]
		this.mutex.Unlock()
		stop := make(chan struct{})
		finished := make(chan struct{})
		parentCtx := ctx
		workerCtx, cancel := context.WithCancel(ctx)
		defer func() {
			close(stop)
			cancel()
			<-finished
		}()
		go func() {
			defer close(finished)
			this.watchDeadline(parentCtx, workerCtx, cancel, stop, key, deadlines)
		}()
		ctx = workerCtx
		// Only the worker writes, and only a successful persisted read may
		// replace the previous deadline. Never queue stale updates.
		updateDeadline := func(sess session.Session) bool {
			readCtx, readCancel := context.WithTimeout(ctx, oidcRefreshTimeout)
			defer readCancel()
			deadline, err := authorizer.VerificationDeadline(readCtx, sess)
			if err != nil {
				logger.WithError(err).Warn("cannot read OIDC verification deadline; retaining previous deadline")
				return false
			}
			if deadline.IsZero() {
				return false
			}
			this.verificationUpdated(sess, deadline)
			return true
		}
		this.refreshLoop(ctx, key, authorizer, updateDeadline)
		return
	}
	this.refreshLoop(ctx, key, authorizer, nil)
}

func (this *oidcRefreshManager) verificationUpdated(sess session.Session, deadline time.Time) {
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.ctx == nil || this.ctx.Err() != nil || deadline.IsZero() {
		return
	}
	updates := this.deadlines[key]
	if updates == nil {
		return
	}
	if previous := this.lastDeadlines[key]; !deadline.After(previous) {
		return
	}
	if this.lastDeadlines == nil {
		this.lastDeadlines = make(map[sessionConnectionKey]time.Time)
	}
	this.lastDeadlines[key] = deadline
	select {
	case updates <- deadline:
	default:
		select {
		case <-updates:
		default:
		}
		select {
		case updates <- deadline:
		default:
		}
	}
}

func (this *oidcRefreshManager) invalidateSession(sess session.Session) {
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.invalidate(key, sess)
}

func (this *oidcRefreshManager) invalidate(key sessionConnectionKey, sess session.Session) {
	this.service.sessionConnections.revoke(key.flow, key.id)
	this.mutex.Lock()
	if this.ctx == nil || this.ctx.Err() != nil {
		this.mutex.Unlock()
		return
	}
	if this.invalidating == nil {
		this.invalidating = make(map[sessionConnectionKey]struct{})
	}
	if _, exists := this.invalidating[key]; exists {
		this.mutex.Unlock()
		return
	}
	this.invalidating[key] = struct{}{}
	this.done.Add(1)
	this.mutex.Unlock()
	go func() {
		defer this.done.Done()
		this.retryDisposal(this.ctx, key, sess)
	}()
}

func (this *oidcRefreshManager) failClosed(flow configuration.FlowName) bool {
	for _, configured := range this.service.Configuration.Flows {
		if configured.Name == flow {
			if conf, ok := configured.Authorization.V.(*configuration.AuthorizationOidcDeviceAuth); ok {
				return conf.ForceDisposeSessionOn != "never"
			}
		}
	}
	return true // Manually constructed managers default to lostAccess.
}

func (this *oidcRefreshManager) watchDeadline(ctx, workerCtx context.Context, cancel context.CancelFunc, stop <-chan struct{}, key sessionConnectionKey, deadlines <-chan time.Time) {
	// Unknown persisted state is not evidence of a fresh verification.
	timer := time.NewTimer(oidcRefreshUnknownGrace)
	defer timer.Stop()
	var current time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case deadline := <-deadlines:
			if !current.IsZero() && !deadline.After(current) {
				continue
			}
			current = deadline
			// The deadline may already have elapsed while a provider was running.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(max(0, time.Until(deadline)))
		case <-timer.C:
			if workerCtx.Err() != nil || ctx.Err() != nil {
				return
			}
			// A refresh completing at the same instant as the timer may lose
			// this race; revocation is deliberately conservative.
			this.service.logger().With("flow", key.flow).With("sessionId", key.id).
				Warn("OIDC verification deadline reached; disposing session")
			this.invalidate(key, nil)
			cancel()
			return
		}
	}
}

func (this *oidcRefreshManager) refreshLoop(ctx context.Context, key sessionConnectionKey, authorizer *authorization.OidcDeviceAuthAuthorizer, updateDeadline func(session.Session) bool) {
	logger := this.service.logger().With("flow", key.flow).With("sessionId", key.id)
	var retryAt time.Time
	first := true
	deadlineKnown := false
	for ctx.Err() == nil {
		sess, err := this.service.sessions.FindBy(ctx, key.flow, key.id, nil)
		if goerrors.Is(err, session.ErrNoSuchSession) {
			return
		}
		if err != nil {
			logger.WithError(err).Warn("cannot find OIDC session for refresh")
			retryAt = time.Now().Add(oidcRefreshRetry)
		} else {
			valid, validErr := session.IsStillValid(ctx, sess)
			if validErr != nil {
				logger.WithError(validErr).Warn("cannot inspect OIDC session validity")
				retryAt = time.Now().Add(oidcRefreshRetry)
			} else if !valid {
				return
			} else {
				if updateDeadline != nil && !deadlineKnown {
					deadlineKnown = updateDeadline(sess)
				}
				if retryAt.IsZero() {
					retryAt, err = authorizer.NextRefreshAt(ctx, sess)
					if goerrors.Is(err, authorization.ErrNoSuchAuthorization) {
						return
					}
					if err != nil {
						logger.WithError(err).Warn("cannot schedule OIDC session refresh")
						retryAt = time.Now().Add(oidcRefreshRetry)
					}
					if retryAt.IsZero() {
						return
					}
				}
			}
		}
		if first && !retryAt.After(time.Now()) {
			// Spread a startup burst of already-due sessions without delaying a
			// missing-token decision by more than a few seconds.
			h := fnv.New32a()
			_, _ = h.Write([]byte(key.id.String()))
			retryAt = time.Now().Add(time.Duration(h.Sum32()%5000) * time.Millisecond)
		}
		first = false
		delay := time.Until(retryAt)
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		select {
		case <-ctx.Done():
			return
		case this.limit <- struct{}{}:
		}
		var lost bool
		func() {
			defer func() { <-this.limit }()
			callCtx, cancel := context.WithTimeout(ctx, oidcRefreshTimeout)
			defer cancel()
			// A new lookup avoids using the state snapshot retained by an old
			// session object after housekeeping has disposed the session.
			current, findErr := this.service.sessions.FindBy(callCtx, key.flow, key.id, nil)
			if findErr != nil {
				err = findErr
				return
			}
			if valid, validErr := session.IsStillValid(callCtx, current); validErr != nil || !valid {
				err = validErr
				if err == nil {
					err = session.ErrNoSuchSession
				}
				return
			}
			sess = current
			retryAt, lost, err = authorizer.RefreshSession(callCtx, current)
		}()
		if ctx.Err() != nil {
			return
		}
		if lost {
			logger.WithError(err).Warn("OIDC session lost access; disposing")
			this.invalidate(key, sess)
			return
		}
		if goerrors.Is(err, session.ErrNoSuchSession) || goerrors.Is(err, authorization.ErrNoSuchAuthorization) {
			return
		}
		if err != nil {
			logger.WithError(err).Warn("OIDC session refresh did not succeed")
		} else if updateDeadline != nil {
			updateDeadline(sess)
		}
		if retryAt.IsZero() || !retryAt.After(time.Now()) {
			retryAt = time.Now().Add(oidcRefreshRetry)
		}
	}
}

func (this *oidcRefreshManager) retryDisposal(ctx context.Context, key sessionConnectionKey, sess session.Session) {
	logger := this.service.logger().With("flow", key.flow).With("sessionId", key.id)
	for ctx.Err() == nil {
		if sess == nil {
			current, err := this.service.sessions.FindBy(ctx, key.flow, key.id, nil)
			if goerrors.Is(err, session.ErrNoSuchSession) {
				return
			}
			if err != nil {
				logger.WithError(err).Warn("cannot find OIDC session while retrying disposal")
			} else {
				sess = current
			}
		}
		if sess != nil {
			if err := this.dispose(ctx, sess); err == nil {
				return
			} else {
				logger.WithError(err).Warn("cannot dispose OIDC session after lost access; retrying")
			}
		}
		timer := time.NewTimer(oidcRefreshRetry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		// Look up again after a failed audited attempt; don't indefinitely
		// retry disposal against a stale snapshot.
		sess = nil
	}
}

func (this *oidcRefreshManager) dispose(ctx context.Context, sess session.Session) error {
	if sess == nil {
		return session.ErrNoSuchSession
	}
	this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
	logger := this.service.logger().With("session", sess)
	callCtx, cancel := context.WithTimeout(ctx, oidcRefreshTimeout)
	defer cancel()
	attempted := false
	_, actionErr, auditErr := this.service.houseKeeper.auditSessionAction(callCtx, sess,
		audit.EventNameHousekeepingSessionDisposeStarted,
		audit.EventNameHousekeepingSessionDisposeCompleted,
		audit.EventReasonOIDCAccessLost,
		func() (bool, error) {
			attempted = true
			return this.service.houseKeeper.disposeWith(callCtx, logger, sess, false, nil, func() {
				this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
			})
		})
	if attempted {
		// Fail closed even if persisting the disposed state failed. Housekeeping
		// retries any incomplete cleanup after the audited attempt.
		this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
	}
	return goerrors.Join(actionErr, auditErr)
}

func (this *oidcRefreshManager) Close() error {
	this.mutex.Lock()
	if this.cancel != nil {
		this.cancel()
	}
	this.mutex.Unlock()
	this.done.Wait()
	return nil
}
