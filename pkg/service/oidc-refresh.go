package service

import (
	"context"
	"encoding/json"
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

// One process coordinator owns refresh workers for persisted sessions. Lightweight
// generation bindings select their original providers while sharing worker state,
// limits and revocation; they never start another manager or shutdown its workers.
type oidcRefreshManager struct {
	service       *service
	coordinator   *oidcRefreshManager
	ctx           context.Context
	cancel        context.CancelFunc
	mutex         sync.Mutex
	workers       map[sessionConnectionKey]context.CancelFunc
	deadlines     map[sessionConnectionKey]chan time.Time
	lastDeadlines map[sessionConnectionKey]time.Time
	invalidating  map[sessionConnectionKey]struct{}
	disposals     map[sessionConnectionKey]context.CancelFunc
	authorizers   map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer
	limit         chan struct{}
	done          sync.WaitGroup
}

func (this *oidcRefreshManager) state() *oidcRefreshManager {
	if this.coordinator != nil {
		return this.coordinator
	}
	return this
}

// Bind callbacks during preparation, but start no workers for a candidate.
func (this *oidcRefreshManager) prepare(svc *service) {
	this.service = svc
	if svc.resources != nil && svc.resources.owner != svc {
		this.coordinator = &svc.resources.owner.oidcRefresh
	}
	facade, ok := svc.authorizer.(*authorization.AuthorizerFacade)
	if !ok {
		return
	}
	authorizers := make(map[configuration.FlowName]*authorization.OidcDeviceAuthAuthorizer)
	for _, flow := range svc.Configuration.Flows {
		conf := configuration.OidcSettings(flow.Authorization.V)
		if conf == nil || !conf.RefreshEnabled() {
			continue
		}
		if authorizer := facade.OidcRefreshAuthorizer(flow.Name); authorizer != nil {
			authorizers[flow.Name] = authorizer
		}
	}
	this.authorizers = authorizers
	for _, authorizer := range authorizers {
		if svc.resources != nil {
			authorizer.OnVerified = this.verifiedForOwner
		} else {
			authorizer.OnVerified = this.verificationUpdated
		}
		authorizer.OnLostAccess = this.invalidateSession
	}
}

func (this *oidcRefreshManager) init(svc *service) error {
	this.start(svc)
	return this.discover()
}

func (this *oidcRefreshManager) start(svc *service) {
	this.prepare(svc)
	if this.coordinator != nil || len(this.authorizers) == 0 && svc.resources == nil {
		return
	}
	this.workers = make(map[sessionConnectionKey]context.CancelFunc)
	this.deadlines = make(map[sessionConnectionKey]chan time.Time)
	this.lastDeadlines = make(map[sessionConnectionKey]time.Time)
	this.invalidating = make(map[sessionConnectionKey]struct{})
	this.disposals = make(map[sessionConnectionKey]context.CancelFunc)
	this.limit = make(chan struct{}, oidcRefreshConcurrency)
	this.ctx, this.cancel = context.WithCancel(context.Background())
}

func (this *oidcRefreshManager) discover() error {
	if this.coordinator != nil || this.ctx == nil {
		return nil
	}
	if err := this.service.sessions.FindAll(this.ctx, func(_ context.Context, sess session.Session) (bool, error) {
		this.register(sess)
		return true, nil
	}, &session.FindOpts{
		DiagnosticConsumer: func(_ context.Context, diagnostic session.FindDiagnostic) error {
			this.service.logger().With("flow", diagnostic.Flow).With("sessionId", diagnostic.Id).
				WithError(diagnostic.Err).Warn("cannot inspect session for OIDC refresh; preserving it")
			return nil
		},
	}); err != nil {
		_ = this.Close()
		return fmt.Errorf("cannot discover OIDC refresh sessions: %w", err)
	}
	return nil
}

func (this *oidcRefreshManager) owned(key sessionConnectionKey) (*oidcRefreshManager, func(), error) {
	if this.service == nil || this.service.resources == nil {
		return this, func() {}, nil
	}
	owner, release, err := this.service.resources.retainSessionOwner(key)
	if err != nil {
		return nil, nil, err
	}
	return &oidcRefreshManager{service: owner, coordinator: this.state(), authorizers: owner.oidcRefresh.authorizers}, release, nil
}

func (this *oidcRefreshManager) verifiedForOwner(sess session.Session, _ time.Time) {
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	owner, release, err := this.owned(key)
	if err != nil {
		return
	}
	defer release()
	if owner.service.runtime != nil && owner.service.runtime.sessionKeyRevoked(key) {
		return
	}
	// A newly authenticated connection may have reused an old session. Use
	// that session's original max-unverified policy, not the new callback's.
	ctx, cancel := context.WithTimeout(context.Background(), oidcRefreshTimeout)
	defer cancel()
	deadline, err := owner.verificationDeadline(ctx, key, sess)
	if err == nil {
		owner.verificationUpdated(sess, deadline)
	}
}

func (this *oidcRefreshManager) register(sess session.Session) {
	state := this.state()
	if state.ctx == nil || state.ctx.Err() != nil || sess == nil {
		return
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	owner, release, err := this.owned(key)
	if err != nil {
		return
	}
	if owner.authorizers[key.flow] == nil || owner.service.runtime != nil && owner.service.runtime.sessionKeyRevoked(key) {
		release()
		return
	}
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.ctx.Err() != nil || state.workers[key] != nil {
		release()
		return
	}
	ctx, cancel := context.WithCancel(state.ctx)
	if owner.failClosed(key.flow) {
		if state.deadlines == nil {
			state.deadlines = make(map[sessionConnectionKey]chan time.Time)
		}
		state.deadlines[key] = make(chan time.Time, 1)
	}
	state.workers[key] = cancel
	state.done.Add(1)
	go func() {
		defer release()
		owner.run(ctx, key)
	}()
}

func (this *oidcRefreshManager) stop(sess session.Session) {
	state := this.state()
	if sess == nil || state.ctx == nil {
		return
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	state.mutex.Lock()
	if cancel := state.workers[key]; cancel != nil {
		cancel()
	}
	state.mutex.Unlock()
}

func (this *oidcRefreshManager) run(ctx context.Context, key sessionConnectionKey) {
	state := this.state()
	defer state.done.Done()
	defer func() {
		state.mutex.Lock()
		delete(state.workers, key)
		delete(state.deadlines, key)
		delete(state.lastDeadlines, key)
		state.mutex.Unlock()
	}()
	logger := this.service.logger().With("flow", key.flow).With("sessionId", key.id)
	authorizer := this.authorizers[key.flow]
	// A deadline read or provider call can block behind another worker. The
	// watchdog therefore owns its timer independently of the refresh loop.
	if this.failClosed(key.flow) {
		state.mutex.Lock()
		deadlines := state.deadlines[key]
		state.mutex.Unlock()
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
			deadline, err := this.verificationDeadline(readCtx, key, sess)
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

// Read only persisted state here: VerificationDeadline takes a refresh shard
// lock which can be held across a slow provider call for another session.
func (this *oidcRefreshManager) verificationDeadline(ctx context.Context, key sessionConnectionKey, sess session.Session) (time.Time, error) {
	if sess.Flow() != key.flow || sess.Id() != key.id {
		return time.Time{}, fmt.Errorf("OIDC session identity changed during deadline read")
	}
	raw, err := sess.AuthorizationToken(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot read OIDC session token: %w", err)
	}
	var token struct {
		AccessToken    string    `json:"access_token"`
		Subject        string    `json:"subject"`
		Issuer         string    `json:"issuer"`
		LastVerifiedAt time.Time `json:"lastVerifiedAt"`
	}
	if err := json.Unmarshal(raw, &token); err != nil || token.AccessToken == "" || token.Subject == "" || token.Issuer == "" || token.LastVerifiedAt.IsZero() {
		return time.Time{}, fmt.Errorf("invalid persisted OIDC verification token: %w", authorization.ErrUnusableAuthorizationToken)
	}
	for _, flow := range this.service.Configuration.Flows {
		if flow.Name == key.flow {
			if conf := configuration.OidcSettings(flow.Authorization.V); conf != nil {
				maxUnverified := conf.RefreshToken.MaxUnverifiedFor.Native()
				if maxUnverified <= 0 {
					maxUnverified = 30 * time.Minute
				}
				return token.LastVerifiedAt.Add(maxUnverified), nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("no OIDC configuration for flow %q", key.flow)
}

func (this *oidcRefreshManager) verificationUpdated(sess session.Session, deadline time.Time) {
	state := this.state()
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.ctx == nil || state.ctx.Err() != nil || deadline.IsZero() {
		return
	}
	updates := state.deadlines[key]
	if updates == nil {
		return
	}
	if previous := state.lastDeadlines[key]; !deadline.After(previous) {
		return
	}
	if state.lastDeadlines == nil {
		state.lastDeadlines = make(map[sessionConnectionKey]time.Time)
	}
	state.lastDeadlines[key] = deadline
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
	if this.service.resources != nil && !this.service.loginSessionCompatible(sess) {
		// A different generation's credential check cannot revoke the grant
		// retained by this session's original provider.
		return
	}
	key := sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}
	this.invalidate(key, sess)
}

func (this *oidcRefreshManager) invalidate(key sessionConnectionKey, sess session.Session) {
	_ = this.service.sessionConnections.revoke(key.flow, key.id)
	state := this.state()
	owner, release, err := this.owned(key)
	if err != nil {
		return
	}
	state.mutex.Lock()
	defer state.mutex.Unlock()
	if state.ctx == nil || state.ctx.Err() != nil {
		release()
		return
	}
	if this.service.resources != nil && !this.service.runtime.hasSession(key) {
		release()
		return
	}
	if state.invalidating == nil {
		state.invalidating = make(map[sessionConnectionKey]struct{})
	}
	if _, exists := state.invalidating[key]; exists {
		release()
		return
	}
	state.invalidating[key] = struct{}{}
	if state.disposals == nil {
		state.disposals = make(map[sessionConnectionKey]context.CancelFunc)
	}
	ctx, cancel := context.WithCancel(state.ctx)
	state.disposals[key] = cancel
	state.done.Add(1)
	go func() {
		defer state.done.Done()
		defer release()
		defer cancel()
		defer func() {
			state.mutex.Lock()
			delete(state.disposals, key)
			state.mutex.Unlock()
		}()
		owner.retryDisposal(ctx, key, sess)
	}()
}

func (this *oidcRefreshManager) failClosed(flow configuration.FlowName) bool {
	for _, configured := range this.service.Configuration.Flows {
		if configured.Name == flow {
			if conf := configuration.OidcSettings(configured.Authorization.V); conf != nil {
				return conf.ForceDisposeSessionOn != "never"
			}
		}
	}
	return true // Manually constructed managers default to lostAccess.
}

func (this *oidcRefreshManager) watchDeadline(ctx, workerCtx context.Context, cancel context.CancelFunc, stop <-chan struct{}, key sessionConnectionKey, deadlines <-chan time.Time) {
	state := this.state()
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
			// The timer and an already queued verification can both be ready.
			// Consult the latest accepted update before committing to revoke.
			state.mutex.Lock()
			latest := state.lastDeadlines[key]
			state.mutex.Unlock()
			if latest.After(current) {
				current = latest
				timer.Reset(max(0, time.Until(current)))
				continue
			}
			select {
			case latest = <-deadlines:
				if latest.After(current) {
					current = latest
					timer.Reset(max(0, time.Until(current)))
					continue
				}
			default:
			}
			this.service.logger().With("flow", key.flow).With("sessionId", key.id).
				Warn("OIDC verification deadline reached; disposing session")
			this.invalidate(key, nil)
			cancel()
			return
		}
	}
}

// finalSessionDeleted is called only after the repository has durably deleted
// the session. The caller must also clear the connection registry tombstone.
func (this *oidcRefreshManager) finalSessionDeleted(flow configuration.FlowName, id session.Id) {
	state := this.state()
	key := sessionConnectionKey{flow: flow, id: id}
	state.mutex.Lock()
	delete(state.invalidating, key)
	if cancel := state.workers[key]; cancel != nil {
		cancel()
	}
	if cancel := state.disposals[key]; cancel != nil {
		cancel()
	}
	state.mutex.Unlock()
}

func (this *oidcRefreshManager) refreshLoop(ctx context.Context, key sessionConnectionKey, authorizer *authorization.OidcDeviceAuthAuthorizer, updateDeadline func(session.Session) bool) {
	state := this.state()
	logger := this.service.logger().With("flow", key.flow).With("sessionId", key.id)
	var retryAt time.Time
	first := true
	deadlineKnown := false
	for ctx.Err() == nil {
		if this.service.runtime != nil && this.service.runtime.sessionKeyRevoked(key) {
			return
		}
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
		case state.limit <- struct{}{}:
		}
		var lost bool
		func() {
			defer func() { <-state.limit }()
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
			if this.service.runtime != nil && this.service.runtime.sessionKeyRevoked(key) {
				err = session.ErrNoSuchSession
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
	_ = this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
	callCtx, cancel := context.WithTimeout(ctx, oidcRefreshTimeout)
	defer cancel()
	owner, current, release, err := this.service.retainSessionAction(callCtx, sess)
	if err != nil {
		return err
	}
	defer release()
	sess = current
	logger := owner.logger().With("session", sess)
	attempted := false
	_, actionErr, auditErr := owner.houseKeeper.auditSessionAction(callCtx, sess,
		audit.EventNameHousekeepingSessionDisposeStarted,
		audit.EventNameHousekeepingSessionDisposeCompleted,
		audit.EventReasonOIDCAccessLost,
		func() (bool, error) {
			attempted = true
			return owner.houseKeeper.disposeWith(callCtx, logger, sess, false, nil, func() {
				_ = this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
			})
		})
	if attempted {
		// Fail closed even if persisting the disposed state failed. Housekeeping
		// retries any incomplete cleanup after the audited attempt.
		_ = this.service.sessionConnections.revoke(sess.Flow(), sess.Id())
	}
	return goerrors.Join(actionErr, auditErr)
}

func (this *oidcRefreshManager) Close() error {
	if this.coordinator != nil {
		return nil // Only the process owner may stop shared workers.
	}
	this.mutex.Lock()
	if this.cancel != nil {
		this.cancel()
	}
	this.mutex.Unlock()
	this.done.Wait()
	return nil
}

func (this *oidcRefreshManager) stopRevoked() {
	if this.service == nil || this.service.runtime == nil {
		return
	}
	state := this.state()
	state.mutex.Lock()
	defer state.mutex.Unlock()
	for key, cancel := range state.workers {
		if this.service.runtime.sessionKeyRevoked(key) {
			cancel()
		}
	}
}
