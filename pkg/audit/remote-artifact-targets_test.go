package audit

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

func TestNewRemoteArtifactTargetsRequiresCapabilityAndOwnsTargets(t *testing.T) {
	var closed atomic.Int32
	capable := &remoteArtifactTargetTestInstance{
		remoteTargetTestInstance: &remoteTargetTestInstance{close: func() error {
			closed.Add(1)
			return nil
		}},
	}
	configurations := configuration.AuditlogTargets{{
		Name: "recordings",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return capable, nil
		}},
	}}
	targets, err := NewRemoteArtifactTargets(t.Context(), "security", configurations)
	require.NoError(t, err)
	require.Len(t, targets.entries, 1)
	require.Equal(t, RemoteTargetScope{Auditlog: "security", Target: "recordings"}, targets.entries[0].scope)
	require.Same(t, capable, targets.entries[0].target.(*validatingRemoteArtifactTarget).artifactTarget)
	require.NoError(t, targets.Close())
	require.NoError(t, targets.Close())
	require.Equal(t, int32(1), closed.Load())

	legacyClosed := atomic.Bool{}
	legacy := configuration.AuditlogTargets{{
		Name: "legacy",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return &remoteTargetTestInstance{close: func() error {
				legacyClosed.Store(true)
				return nil
			}}, nil
		}},
	}}
	targets, err = NewRemoteArtifactTargets(t.Context(), "security", legacy)
	require.Nil(t, targets)
	require.ErrorContains(t, err, "does not support remote artifacts")
	require.True(t, errors.Config.IsErr(err))
	require.True(t, legacyClosed.Load())
}
