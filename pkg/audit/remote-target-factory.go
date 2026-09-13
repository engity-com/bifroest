package audit

import (
	"context"
	goerrors "errors"
	"reflect"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

type RemoteTargetScope struct {
	Auditlog configuration.AuditlogName
	Target   configuration.AuditlogTargetName
}

func (this RemoteTargetScope) Validate() error {
	if err := this.Auditlog.Validate(); err != nil {
		return errors.Config.Newf("illegal remote target auditlog: %w", err)
	}
	if err := this.Target.Validate(); err != nil {
		return errors.Config.Newf("illegal remote target name: %w", err)
	}
	return nil
}

// RemoteTargetDestinationIdentity is a stable, canonical description of the
// destination selected by a custom target configuration. It must change
// whenever the effective destination or tenant changes, including a rendered
// username when it scopes storage, but must not contain passwords, tokens,
// private keys, or other secret credential material.
type RemoteTargetDestinationIdentity string

// RemoteTargetSettings describe the effective, non-secret delivery settings
// returned by a custom target factory from the same snapshot as the target.
type RemoteTargetSettings struct {
	DestinationIdentity   RemoteTargetDestinationIdentity
	PublishAttemptTimeout time.Duration
}

// RemoteTargetFactory constructs a custom target and its effective settings.
// DestinationIdentity must be non-empty and PublishAttemptTimeout positive.
type RemoteTargetFactory[C configuration.AuditlogTargetV] func(context.Context, RemoteTargetScope, C) (RemoteTarget, RemoteTargetSettings, error)

type preparedRemoteTargetFactory[C configuration.AuditlogTargetV] func(context.Context, RemoteTargetScope, C) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error)

type remoteTargetFactory func(context.Context, RemoteTargetScope, configuration.AuditlogTargetV) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error)

var configurationTypeToRemoteTargetFactory = make(map[reflect.Type]remoteTargetFactory)

// RegisterRemoteTarget binds a concrete target configuration to its runtime
// implementation. Registrations are expected during package initialization.
func RegisterRemoteTarget[C configuration.AuditlogTargetV](configurationFactory configuration.AuditlogTargetVFactory, factory RemoteTargetFactory[C]) RemoteTargetFactory[C] {
	registerRemoteTarget(configurationFactory, func(ctx context.Context, scope RemoteTargetScope, conf C) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error) {
		target, settings, err := factory(ctx, scope, conf)
		if err != nil {
			return nil, 0, remoteDeliveryDestinationFingerprint{}, err
		}
		timeout, fingerprint, settingsErr := customRemoteDeliveryTargetSettings(conf, settings)
		if settingsErr != nil {
			if isNilRemoteValue(target) {
				return nil, 0, remoteDeliveryDestinationFingerprint{}, settingsErr
			}
			return nil, 0, remoteDeliveryDestinationFingerprint{}, goerrors.Join(settingsErr, target.Close())
		}
		return target, timeout, fingerprint, nil
	})
	return factory
}

func registerPreparedRemoteTarget[C configuration.AuditlogTargetV](configurationFactory configuration.AuditlogTargetVFactory, factory preparedRemoteTargetFactory[C]) preparedRemoteTargetFactory[C] {
	registerRemoteTarget(configurationFactory, factory)
	return factory
}

func registerRemoteTarget[C configuration.AuditlogTargetV](configurationFactory configuration.AuditlogTargetVFactory, factory preparedRemoteTargetFactory[C]) {
	if configurationFactory == nil {
		panic("nil remote audit target configuration factory")
	}
	if factory == nil {
		panic("nil remote audit target factory")
	}
	configurationType := reflect.TypeFor[C]()
	if configurationType.Kind() == reflect.Interface {
		panic("remote audit target configuration type must be concrete")
	}
	if _, exists := configurationTypeToRemoteTargetFactory[configurationType]; exists {
		panic("duplicate remote audit target factory for " + configurationType.String())
	}
	configured := configurationFactory()
	if isNilRemoteValue(configured) || reflect.TypeOf(configured) != configurationType {
		panic("remote audit target configuration factory does not produce " + configurationType.String())
	}
	configuration.RegisterAuditlogTargetV(configurationFactory)
	configurationTypeToRemoteTargetFactory[configurationType] = func(ctx context.Context, scope RemoteTargetScope, raw configuration.AuditlogTargetV) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error) {
		conf, ok := raw.(C)
		if !ok {
			return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot use remote target configuration %T as %s", raw, configurationType)
		}
		return factory(ctx, scope, conf)
	}
}

func NewRemoteTarget(ctx context.Context, auditlogName configuration.AuditlogName, conf *configuration.AuditlogTarget) (RemoteTarget, error) {
	entry, err := newRemoteTargetEntry(ctx, auditlogName, conf)
	return entry.target, err
}

func newRemoteTargetEntry(ctx context.Context, auditlogName configuration.AuditlogName, conf *configuration.AuditlogTarget) (remoteTargetEntry, error) {
	if conf == nil {
		return remoteTargetEntry{}, errors.Config.Newf("nil remote audit target configuration")
	}
	if err := conf.Validate(); err != nil {
		return remoteTargetEntry{}, errors.Config.Newf("remote audit target %q is invalid: %w", conf.Name, err)
	}
	scope := RemoteTargetScope{Auditlog: auditlogName, Target: conf.Name}
	if err := scope.Validate(); err != nil {
		return remoteTargetEntry{}, err
	}
	factory, exists := configurationTypeToRemoteTargetFactory[reflect.TypeOf(conf.V)]
	if !exists {
		return remoteTargetEntry{}, errors.Config.Newf("remote audit target %q of auditlog %q has unsupported configuration type %T", conf.Name, auditlogName, conf.V)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target, publishAttemptTimeout, destinationFingerprint, err := factory(ctx, scope, conf.V)
	if err != nil {
		return remoteTargetEntry{}, errors.System.Newf("cannot initialize remote audit target %q of auditlog %q: %w", conf.Name, auditlogName, err)
	}
	if isNilRemoteValue(target) {
		return remoteTargetEntry{}, errors.System.Newf("remote audit target %q of auditlog %q factory returned nil", conf.Name, auditlogName)
	}
	return remoteTargetEntry{
		scope:                  scope,
		target:                 &validatingRemoteTarget{target: target},
		publishAttemptTimeout:  publishAttemptTimeout,
		destinationFingerprint: destinationFingerprint,
	}, nil
}

type validatingRemoteTarget struct {
	target RemoteTarget
}

func (this *validatingRemoteTarget) Publish(ctx context.Context, segment SealedSegment) error {
	if err := segment.ValidateContext(ctx); err != nil {
		return err
	}
	return this.target.Publish(ctx, segment)
}

func (this *validatingRemoteTarget) Close() error {
	return this.target.Close()
}

type remoteTargetEntry struct {
	scope                  RemoteTargetScope
	target                 RemoteTarget
	publishAttemptTimeout  time.Duration
	destinationFingerprint remoteDeliveryDestinationFingerprint
}

// RemoteTargets owns a target set in configuration order. It starts no
// background work; delivery orchestration is intentionally separate.
type RemoteTargets struct {
	mutex    sync.Mutex
	entries  []remoteTargetEntry
	closed   bool
	closeErr error
}

func NewRemoteTargets(ctx context.Context, auditlogName configuration.AuditlogName, configurations configuration.AuditlogTargets) (*RemoteTargets, error) {
	if err := auditlogName.Validate(); err != nil {
		return nil, errors.Config.Newf("illegal remote target auditlog: %w", err)
	}
	if err := configurations.Validate(); err != nil {
		return nil, errors.Config.Newf("remote targets of auditlog %q are invalid: %w", auditlogName, err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result := &RemoteTargets{entries: make([]remoteTargetEntry, 0, len(configurations))}
	for index := range configurations {
		entry, err := newRemoteTargetEntry(ctx, auditlogName, &configurations[index])
		if err != nil {
			return nil, goerrors.Join(err, result.Close())
		}
		result.entries = append(result.entries, entry)
	}
	return result, nil
}

func (this *RemoteTargets) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.closeErr
	}
	this.closed = true
	for index := len(this.entries) - 1; index >= 0; index-- {
		entry := this.entries[index]
		if err := entry.target.Close(); err != nil {
			this.closeErr = goerrors.Join(this.closeErr, errors.System.Newf("cannot close remote audit target %q of auditlog %q: %w", entry.scope.Target, entry.scope.Auditlog, err))
		}
	}
	return this.closeErr
}
