package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

type runtimeSessionAction struct {
	gate  chan struct{}
	users int
}

func (this *runtimeResources) retainSessionOwner(key sessionConnectionKey) (*service, func(), error) {
	generation, release, err := this.owner.runtime.retainSessionOwner(key)
	if err != nil {
		return nil, nil, err
	}
	if generation == this.owner.generation {
		return this.owner, release, nil // Also used during initial preparation.
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	for svc := range this.views {
		if svc.generation == generation {
			return svc, release, nil
		}
	}
	release()
	return nil, nil, fmt.Errorf("session runtime owner has no provider view")
}

func (this *service) retainSessionOwner(sess session.Session) (*service, func(), error) {
	if this.resources == nil {
		return this, func() {}, nil
	}
	return this.resources.retainSessionOwner(sessionConnectionKey{flow: sess.Flow(), id: sess.Id()})
}

// An existing OIDC grant is owned by its original client/issuer/refresh policy.
// Do not rotate that grant using changed settings while authenticating a new
// connection. Identical settings can reuse it under the shared grant lock.
func (this *service) loginSessionCompatible(sess session.Session) bool {
	if this.runtime == nil {
		return true
	}
	if !this.runtime.sessionCompatible(this.generation, sess) {
		// A newly created associated session can become visible to the next
		// credential-verified login before its creator registers the in-memory
		// lease. Recognize only its immutable, already-persisted exact owner;
		// never guess ownership for an unstamped/old session.
		if this.generation.ownership == nil || this.runtime.hasSession(sessionConnectionKey{flow: sess.Flow(), id: sess.Id()}) {
			return false
		}
		provider, ok := sess.(session.RuntimeOwnershipSession)
		if !ok {
			return false
		}
		owner, err := provider.RuntimeOwnership(context.Background())
		if err != nil || owner == nil || !owner.Matches(this.generation.ownership.Flows[sess.Flow()]) {
			return false
		}
		revoked, err := provider.RuntimeRevoked(context.Background())
		if err != nil || revoked || this.runtime.bindSession(this.generation, sess, true) != nil {
			return false
		}
	}
	if this.resources == nil {
		return true
	}
	owner, release, err := this.retainSessionOwner(sess)
	if err != nil {
		return false
	}
	defer release()
	if this.Watch == configuration.WatchModeReuse && owner != this {
		var previous, current configuration.Environment
		for _, flow := range owner.Configuration.Flows {
			if flow.Name == sess.Flow() {
				previous = flow.Environment
				break
			}
		}
		for _, flow := range this.Configuration.Flows {
			if flow.Name == sess.Flow() {
				current = flow.Environment
				break
			}
		}
		if !configuration.EnvironmentCanReuse(previous, current) {
			return false
		}
	}
	settings := func(svc *service) *configuration.AuthorizationOidcDeviceAuth {
		for _, flow := range svc.Configuration.Flows {
			if flow.Name == sess.Flow() {
				return configuration.OidcSettings(flow.Authorization.V)
			}
		}
		return nil
	}
	before, after := settings(owner), settings(this)
	if before == nil || after == nil {
		return before == nil && after == nil
	}
	left, right := *before, *after
	// SSH login messages are presentation, not retained-grant policy.
	left.Ssh, right.Ssh = configuration.AuthorizationOidcSsh{}, configuration.AuthorizationOidcSsh{}
	if !left.IsEqualTo(&right) {
		return false
	}
	if persistence := this.runtime.persistence; persistence != nil {
		oldProvider, newProvider := owner.runtimeOidcAuthorizer(sess.Flow()), this.runtimeOidcAuthorizer(sess.Flow())
		if oldProvider == nil || newProvider == nil {
			return false
		}
		oldDigest, oldErr := oldProvider.RuntimeDigest(persistence.key)
		newDigest, newErr := newProvider.RuntimeDigest(persistence.key)
		return oldErr == nil && newErr == nil && oldDigest == newDigest
	}
	return true
}

// Serialize destructive session work across housekeeping, OIDC and management.
// Entries disappear with the last waiter; no unbounded per-session lock cache.
func (this *runtimeResources) lockSessionAction(ctx context.Context, key sessionConnectionKey) (func(), error) {
	this.actionsMutex.Lock()
	entry := this.actions[key]
	if entry == nil {
		entry = &runtimeSessionAction{gate: make(chan struct{}, 1)}
		this.actions[key] = entry
	}
	entry.users++
	this.actionsMutex.Unlock()
	releaseUser := func() {
		this.actionsMutex.Lock()
		entry.users--
		if entry.users == 0 {
			delete(this.actions, key)
		}
		this.actionsMutex.Unlock()
	}
	select {
	case <-ctx.Done():
		releaseUser()
		return nil, ctx.Err()
	case entry.gate <- struct{}{}:
		return sync.OnceFunc(func() { <-entry.gate; releaseUser() }), nil
	}
}

func (this *service) retainSessionAction(ctx context.Context, sess session.Session) (*service, session.Session, func(), error) {
	owner, release, err := this.retainSessionOwner(sess)
	if err != nil || this.resources == nil {
		return owner, sess, release, err
	}
	unlock, err := this.resources.lockSessionAction(ctx, sessionConnectionKey{flow: sess.Flow(), id: sess.Id()})
	if err != nil {
		release()
		return nil, nil, nil, err
	}
	finish := sync.OnceFunc(func() { unlock(); release() })
	if err := ctx.Err(); err != nil {
		finish()
		return nil, nil, nil, err
	}
	if this.runtime.sessionOwner(sess) != owner.generation {
		finish()
		return nil, nil, nil, session.ErrNoSuchSession
	}
	current, err := owner.sessions.FindBy(ctx, sess.Flow(), sess.Id(), nil)
	if err != nil {
		finish()
		return nil, nil, nil, err
	}
	return owner, current, finish, nil
}

func (this *runtimeResources) retainedViews() ([]*service, func()) {
	this.mutex.Lock()
	candidates := make([]*service, 0, len(this.views)+1)
	candidates = append(candidates, this.owner)
	for svc := range this.views {
		if svc != this.owner {
			candidates = append(candidates, svc)
		}
	}
	this.mutex.Unlock()
	var views []*service
	var releases []func()
	for _, svc := range candidates {
		if release, err := svc.retainRuntime(); err == nil {
			views = append(views, svc)
			releases = append(releases, release)
		}
	}
	return views, func() {
		for _, release := range releases {
			release()
		}
	}
}

// Called only after the registry has released its lock. These operations cancel
// revoked workers and wake one existing housekeeping loop, never start another.
func (this *runtimeResources) maintenanceChanged() {
	this.owner.oidcRefresh.stopRevoked()
	this.owner.houseKeeper.requestRun()
}
