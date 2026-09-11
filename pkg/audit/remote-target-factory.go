package audit

import (
	"context"
	goerrors "errors"
	"reflect"
	"sync"

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

type RemoteTargetFactory[C configuration.AuditlogTargetV] func(context.Context, RemoteTargetScope, C) (RemoteTarget, error)

type remoteTargetFactory func(context.Context, RemoteTargetScope, configuration.AuditlogTargetV) (RemoteTarget, error)

var configurationTypeToRemoteTargetFactory = make(map[reflect.Type]remoteTargetFactory)

// RegisterRemoteTarget binds a concrete target configuration to its runtime
// implementation. Registrations are expected during package initialization.
func RegisterRemoteTarget[C configuration.AuditlogTargetV](configurationFactory configuration.AuditlogTargetVFactory, factory RemoteTargetFactory[C]) RemoteTargetFactory[C] {
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
	configurationTypeToRemoteTargetFactory[configurationType] = func(ctx context.Context, scope RemoteTargetScope, raw configuration.AuditlogTargetV) (RemoteTarget, error) {
		conf, ok := raw.(C)
		if !ok {
			return nil, errors.Config.Newf("cannot use remote target configuration %T as %s", raw, configurationType)
		}
		return factory(ctx, scope, conf)
	}
	return factory
}

func NewRemoteTarget(ctx context.Context, auditlogName configuration.AuditlogName, conf *configuration.AuditlogTarget) (RemoteTarget, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil remote audit target configuration")
	}
	if err := conf.Validate(); err != nil {
		return nil, errors.Config.Newf("remote audit target %q is invalid: %w", conf.Name, err)
	}
	scope := RemoteTargetScope{Auditlog: auditlogName, Target: conf.Name}
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	factory, exists := configurationTypeToRemoteTargetFactory[reflect.TypeOf(conf.V)]
	if !exists {
		return nil, errors.Config.Newf("remote audit target %q of auditlog %q has unsupported configuration type %T", conf.Name, auditlogName, conf.V)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target, err := factory(ctx, scope, conf.V)
	if err != nil {
		return nil, errors.System.Newf("cannot initialize remote audit target %q of auditlog %q: %w", conf.Name, auditlogName, err)
	}
	if isNilRemoteValue(target) {
		return nil, errors.System.Newf("remote audit target %q of auditlog %q factory returned nil", conf.Name, auditlogName)
	}
	return &validatingRemoteTarget{target: target}, nil
}

type validatingRemoteTarget struct {
	target RemoteTarget
}

func (this *validatingRemoteTarget) Publish(ctx context.Context, segment SealedSegment) error {
	if err := segment.Validate(); err != nil {
		return err
	}
	return this.target.Publish(ctx, segment)
}

func (this *validatingRemoteTarget) Close() error {
	return this.target.Close()
}

type remoteTargetEntry struct {
	scope  RemoteTargetScope
	target RemoteTarget
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
	result := &RemoteTargets{entries: make([]remoteTargetEntry, 0, len(configurations))}
	for index := range configurations {
		conf := &configurations[index]
		target, err := NewRemoteTarget(ctx, auditlogName, conf)
		if err != nil {
			return nil, goerrors.Join(err, result.Close())
		}
		result.entries = append(result.entries, remoteTargetEntry{
			scope:  RemoteTargetScope{Auditlog: auditlogName, Target: conf.Name},
			target: target,
		})
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
