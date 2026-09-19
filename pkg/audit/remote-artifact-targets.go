package audit

import (
	"context"
	goerrors "errors"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

type remoteArtifactTargetEntry struct {
	scope                  RemoteTargetScope
	target                 RemoteArtifactTarget
	publishTarget          RemoteArtifactTarget
	publishAttemptTimeout  time.Duration
	destinationFingerprint remoteDeliveryDestinationFingerprint
}

// RemoteArtifactTargets owns an artifact-capable target set in configuration
// order. It performs no publication and starts no background work.
type RemoteArtifactTargets struct {
	targets *RemoteTargets
	entries []remoteArtifactTargetEntry
}

func NewRemoteArtifactTargets(ctx context.Context, auditlogName configuration.AuditlogName, configurations configuration.AuditlogTargets) (*RemoteArtifactTargets, error) {
	targets, err := NewRemoteTargets(ctx, auditlogName, configurations)
	if err != nil {
		return nil, err
	}
	result := &RemoteArtifactTargets{targets: targets, entries: make([]remoteArtifactTargetEntry, 0, len(targets.entries))}
	for _, entry := range targets.entries {
		target, ok := entry.target.(RemoteArtifactTarget)
		if !ok {
			capabilityErr := errors.Config.Newf("remote target %q of auditlog %q does not support remote artifacts", entry.scope.Target, entry.scope.Auditlog)
			return nil, goerrors.Join(capabilityErr, targets.Close())
		}
		result.entries = append(result.entries, remoteArtifactTargetEntry{
			scope:                  entry.scope,
			target:                 target,
			publishTarget:          remoteArtifactPublishTarget(target),
			publishAttemptTimeout:  entry.publishAttemptTimeout,
			destinationFingerprint: entry.destinationFingerprint,
		})
	}
	return result, nil
}

func remoteArtifactPublishTarget(target RemoteArtifactTarget) RemoteArtifactTarget {
	if validating, ok := target.(*validatingRemoteArtifactTarget); ok && !isNilRemoteValue(validating.artifactTarget) {
		return validating.artifactTarget
	}
	return target
}

func (this *RemoteArtifactTargets) Close() error {
	if this == nil || this.targets == nil {
		return nil
	}
	return this.targets.Close()
}
