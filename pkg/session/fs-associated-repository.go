package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type associationSubject struct {
	flow            configuration.FlowName
	issuer, subject string
}
type associationLock struct {
	gate       chan struct{}
	references int
}

func (this *FsRepository) lockAssociation(ctx context.Context, key associationSubject) (func(), error) {
	this.associationMutex.Lock()
	if this.associationLocks == nil {
		this.associationLocks = make(map[associationSubject]*associationLock)
	}
	lock := this.associationLocks[key]
	if lock == nil {
		lock = &associationLock{gate: make(chan struct{}, 1)}
		this.associationLocks[key] = lock
	}
	lock.references++
	this.associationMutex.Unlock()
	releaseReference := func() {
		this.associationMutex.Lock()
		defer this.associationMutex.Unlock()
		lock.references--
		if lock.references == 0 {
			delete(this.associationLocks, key)
		}
	}
	select {
	case <-ctx.Done():
		releaseReference()
		return nil, ctx.Err()
	case lock.gate <- struct{}{}:
		return func() { <-lock.gate; releaseReference() }, nil
	}
}

func (this *FsRepository) ResolveAssociatedSession(ctx context.Context, request AssociationRequest) (Session, bool, error) {
	if err := request.Flow.Validate(); err != nil {
		return nil, false, fmt.Errorf("invalid session association flow")
	}
	if err := request.Identity.Validate(); err != nil {
		return nil, false, fmt.Errorf("invalid verified session identity")
	}
	if !request.Identity.IsAuthenticated() {
		return nil, false, ErrAnonymousAssociation
	}
	if request.Remote == nil || request.ResolveTarget == nil {
		return nil, false, fmt.Errorf("session association needs remote metadata and a target resolver")
	}
	unlock, err := this.lockAssociation(ctx, associationSubject{request.Flow, request.Identity.Issuer, request.Identity.Subject})
	if err != nil {
		return nil, false, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := this.checkAssociationWriter(); err != nil {
		return nil, false, err
	}
	var found Session
	err = this.iterateFlowDirs(ctx, request.Flow, func(id Id, _ string) (bool, error) {
		candidate, err := this.FindBy(ctx, request.Flow, id, nil)
		if errors.Is(err, ErrNoSuchSession) {
			return true, nil
		}
		// FindBy reports association-bearing damaged entries as
		// ErrInvalidAssociation. A corrupt, unbound legacy entry is not an
		// ownership candidate: preserve it for management diagnostics without
		// preventing a fresh verified management login in the same flow.
		if errors.Is(err, ErrCorruptSession) {
			this.logger().With("flow", request.Flow).With("sessionId", id).Warn("preserving corrupt unbound session during association selection")
			return true, nil
		}
		if err != nil {
			return false, err
		}
		association, err := AssociationOf(ctx, candidate)
		if err != nil {
			return false, err
		}
		// Neither client name nor session ID may claim an unbound legacy session.
		if association == nil || !association.SameSubject(request.Identity) {
			return true, nil
		}
		valid, err := IsStillValid(ctx, candidate)
		if err != nil || !valid {
			return err == nil, err
		}
		info, err := candidate.Info(ctx)
		if err != nil {
			return false, err
		}
		created, err := info.Created(ctx)
		if err != nil {
			return false, err
		}
		target, err := request.ResolveTarget(ctx, Reference{Flow: request.Flow, Id: id, Created: created})
		if err != nil {
			return false, err
		}
		if err := target.Validate(); err != nil {
			return false, err
		}
		if association.Target != target {
			return true, nil
		}
		if request.Compatible != nil {
			compatible, err := request.Compatible(ctx, candidate)
			if err != nil || !compatible {
				return err == nil, err
			}
		}
		found = candidate
		return false, nil
	}, nil)
	if err != nil {
		return nil, false, err
	}
	if found != nil {
		// Recheck disposal/expiry after callbacks. No touching access time, tokens,
		// or connections until the caller commits its own authenticated connection.
		current, err := this.FindBy(ctx, request.Flow, found.Id(), nil)
		if err != nil && !errors.Is(err, ErrNoSuchSession) {
			return nil, false, err
		}
		if err == nil {
			valid, err := IsStillValid(ctx, current)
			if err != nil {
				return nil, false, err
			}
			if valid {
				if err := this.checkAssociationWriter(); err != nil {
					return nil, false, err
				}
				if err := ctx.Err(); err != nil {
					return nil, false, err
				}
				return current, false, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	id, err := uuid.NewUUID()
	if err != nil {
		return nil, false, err
	}
	createdAt := time.Now().Truncate(time.Millisecond)
	preview := &fs{}
	preview.init(this, request.Flow, Id(id))
	preview.info.createdAt = createdAt
	preview.info.VRemoteUser = request.Remote.User()
	preview.info.VRemoteHost = request.Remote.Host().Clone()
	target, err := request.ResolveTarget(ctx, Reference{Flow: request.Flow, Id: Id(id), Created: &preview.info.created})
	if err != nil {
		return nil, false, err
	}
	association, err := NewAssociation(request.Identity, target)
	if err != nil {
		return nil, false, err
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := validateFsRepositoryProcessLock(this.processLock, this.processLockPath()); err != nil {
		return nil, false, err
	}
	created, err := this.create(ctx, request.Flow, request.Remote, request.AuthorizationToken, Id(id), &association, createdAt)
	return created, err == nil, err
}

func (this *FsRepository) checkAssociationWriter() error {
	this.mutex.RLock()
	defer this.mutex.RUnlock()
	return validateFsRepositoryProcessLock(this.processLock, this.processLockPath())
}

func (this *FsRepository) processLockPath() string {
	if this.processLock != nil {
		return this.processLock.path
	}
	return ""
}
