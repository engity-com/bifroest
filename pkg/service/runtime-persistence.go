package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/session"
)

var errUncertainRuntimeCommit = errors.New("runtime persistence is uncertain; admission stopped")

type runtimePersistence struct {
	repository session.RuntimeRepository
	revoker    session.RuntimeSessionRevoker
	key        []byte
	process    session.RuntimeRevision
	failed     func(error)
}

func (this *service) openRuntimePersistence(ctx context.Context) (*session.RuntimeState, error) {
	repository, ok := this.sessions.(session.RuntimeRepository)
	if !ok {
		return nil, fmt.Errorf("session repository does not support persistent runtime ownership")
	}
	key, err := repository.RuntimeKey(ctx)
	if err != nil {
		return nil, err
	}
	previous, err := repository.RuntimeState(ctx)
	if err != nil {
		return nil, err
	}
	process, err := session.NewRuntimeRevision()
	if err != nil {
		return nil, err
	}
	this.runtime.persistence = &runtimePersistence{repository: repository, key: key, process: process, failed: this.failRuntimePersistence}
	this.runtime.persistence.revoker, ok = this.sessions.(session.RuntimeSessionRevoker)
	if !ok {
		return nil, fmt.Errorf("session repository does not support durable revocation")
	}
	return previous, nil
}

func (this *service) initializeRuntimePersistence(ctx context.Context, previous *session.RuntimeState) error {
	if err := this.prepareRuntimeOwnership(previous); err != nil {
		return err
	}
	var expected session.RuntimeRevision
	if previous != nil {
		expected = previous.Revision
	}
	result := this.runtime.persistence.repository.CommitRuntimeState(ctx, expected, *this.generation.ownership)
	if result.Uncertain || !result.Published {
		return errors.Join(fmt.Errorf("cannot initialize persistent runtime ownership"), result.Err)
	}
	if result.Err != nil {
		// No listener has been admitted yet. Do not start with uncertain durability.
		return fmt.Errorf("runtime ownership published but not durably synchronized: %w", result.Err)
	}
	return nil
}

func (this *service) failRuntimePersistence(err error) {
	this.resources.mutex.Lock()
	listeners := this.resources.listeners
	this.resources.mutex.Unlock()
	if listeners != nil {
		listeners.cancel(err)
	}
	this.logger().WithError(err).Error("runtime persistence failed; new admission stopped")
}

func (this *service) prepareRuntimeOwnership(previous *session.RuntimeState) error {
	persistence := this.runtime.persistence
	if persistence == nil {
		return nil
	}
	digests, err := this.generation.snapshot.RuntimeDigests(persistence.key)
	if err != nil {
		return err
	}
	for _, flow := range this.Configuration.Flows {
		value := digests[flow.Name]
		extra := ""
		// Until these resource-owning providers expose a complete restart proof,
		// never reinterpret an old token using freshly initialized dependencies.
		switch flow.Environment.V.(type) {
		case *configuration.EnvironmentDummy, *configuration.EnvironmentManagement:
		default:
			extra = string(persistence.process)
		}
		switch auth := flow.Authorization.V.(type) {
		case *configuration.AuthorizationNone:
		case *configuration.AuthorizationSimple:
			if !auth.TrustedUserCAsFile.IsZero() {
				extra += string(persistence.process)
			}
			for _, entry := range auth.Entries {
				if !entry.PasswordFile.IsZero() || !entry.AuthorizedKeysFile.IsZero() {
					extra += string(persistence.process)
					break
				}
			}
		default:
			if settings := configuration.OidcSettings(flow.Authorization.V); settings != nil {
				if provider := this.runtimeOidcAuthorizer(flow.Name); provider != nil {
					resolved, err := provider.RuntimeDigest(persistence.key)
					if err != nil {
						return err
					}
					extra += resolved
				} else {
					extra += string(persistence.process)
				}
			} else {
				extra += string(persistence.process)
			}
		}
		if extra != "" {
			mac := hmac.New(sha256.New, persistence.key)
			_, _ = mac.Write([]byte("bifroest-runtime-owner-dependencies-v1\x00" + value.Owner + "\x00" + extra))
			value.Owner = hex.EncodeToString(mac.Sum(nil))
		}
		digests[flow.Name] = value
	}
	this.generation.ownership, err = session.AdvanceRuntimeState(previous, digests)
	return err
}

func (this *service) runtimeOidcAuthorizer(flow configuration.FlowName) *authorization.OidcDeviceAuthAuthorizer {
	if discovery, ok := this.authorizer.(interface {
		OidcRefreshAuthorizer(configuration.FlowName) *authorization.OidcDeviceAuthAuthorizer
	}); ok {
		return discovery.OidcRefreshAuthorizer(flow)
	}
	return nil
}

// Provider preparation can resolve an OIDC client/discovery change even when
// only presentation text changed in YAML. Such a change is not cosmetic.
// The candidate is still unpublished; no registry lock or external callback is
// involved while refining its in-memory revisions.
func (this *service) refineRuntimeAccessRevisions() {
	current := this.generation
	if current.parent == nil || current.ownership == nil || current.parent.ownership == nil {
		return
	}
	for name, after := range current.ownership.Flows {
		before, exists := current.parent.ownership.Flows[name]
		if !exists || before.OwnerDigest == after.OwnerDigest {
			continue
		}
		binding := current.flows[name]
		binding.actions = &runtimeFlowRevision{}
		if this.Watch == configuration.WatchModeReconnect {
			binding.admission = &runtimeFlowRevision{}
		}
		current.flows[name] = binding
	}
}

func (this *service) runtimeCreationContext(ctx context.Context, flow configuration.FlowName) context.Context {
	if this.generation != nil && this.generation.ownership != nil {
		return session.WithRuntimeOwnership(ctx, this.generation.ownership.Flows[flow])
	}
	return ctx
}

// Called with transition held, never a registry/topology/publication lock.
func (this *runtimeGenerations) prepareActivation(ctx context.Context, candidate *runtimeGeneration) (error, error) {
	this.mutex.Lock()
	err := this.checkActivationLocked(ctx, candidate)
	this.mutex.Unlock()
	if err != nil || this.persistence == nil {
		return nil, err
	}
	if candidate.ownership == nil || candidate.parent.ownership == nil {
		return nil, fmt.Errorf("runtime candidate has no prepared persistent ownership")
	}
	result := this.persistence.repository.CommitRuntimeState(ctx, candidate.parent.ownership.Revision, *candidate.ownership)
	if result.Uncertain || !result.Published && (errors.Is(result.Err, session.ErrRuntimeStateConflict) || errors.Is(result.Err, session.ErrInvalidRuntimeState) || result.Err == nil) {
		err := errors.Join(errUncertainRuntimeCommit, result.Err)
		this.stopState()
		this.persistence.failed(err)
		return nil, err
	}
	if !result.Published {
		return nil, result.Err
	}
	return result.Err, nil
}
