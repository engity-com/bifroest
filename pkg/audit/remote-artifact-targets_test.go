package audit

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

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

func TestRemoteArtifactDeliveryValidatesLocalBytesBeforeAnyTargetCall(t *testing.T) {
	for _, configured := range []bool{true, false} {
		name := "direct"
		if configured {
			name = "configured"
		}
		t.Run(name, func(t *testing.T) {
			identity, directory, source := newRemoteArtifactDeliveryTestSource(t)
			content := []byte("sealed recording")
			artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "recording.cast.zst", content)
			var calls atomic.Int32
			var remoteConflict atomic.Bool
			remoteConflict.Store(true)
			published := make(chan []byte, 1)
			publish := func(_ context.Context, artifact RemoteArtifact) error {
				calls.Add(1)
				if remoteConflict.Load() {
					return errors.Config.Newf("existing remote object conflicts with artifact")
				}
				data, err := io.ReadAll(artifact.Content())
				if err == nil {
					published <- data
				}
				return err
			}
			var targets *RemoteArtifactTargets
			if configured {
				var err error
				targets, err = NewRemoteArtifactTargets(t.Context(), "security", configuration.AuditlogTargets{{
					Name: "archive",
					V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
						return &remoteArtifactTargetTestInstance{remoteTargetTestInstance: &remoteTargetTestInstance{}, publishArtifact: publish}, nil
					}},
				}})
				require.NoError(t, err)
			} else {
				targets = remoteArtifactDeliveryTestTargets(remoteArtifactDeliveryTestEntry("archive", remoteArtifactDeliveryTestFingerprint("archive"), publish))
			}
			receipts := newRemoteArtifactDeliveryTestReceipts(t, identity, []RemoteArtifact{artifact}, targets)
			tampered, err := NewRemoteArtifact(artifact.ProducerId(), artifact.FileName(), artifact.Digest(), artifact.Size(), bytes.NewReader([]byte("sealed recordinG")))
			require.NoError(t, err)
			source.set(tampered)
			auditor := &remoteArtifactDeliveryTestAuditor{}
			options := remoteArtifactDeliveryTestOptions()
			options.auditor = auditor
			delivery := newRemoteArtifactDeliveryTestCoordinator(t, directory, source, receipts, targets, options)
			require.NoError(t, delivery.Start())
			require.Eventually(t, func() bool { return len(auditor.snapshot()) > 0 }, time.Second, time.Millisecond)
			require.Zero(t, calls.Load())
			receipt, exists, err := receipts.store.load(artifact)
			require.NoError(t, err)
			require.True(t, exists)
			require.Empty(t, receipt.Targets[0].AcknowledgedAt)
			require.Empty(t, receipt.Targets[0].SuccessAuditedAt)
			for _, event := range auditor.snapshot() {
				require.Equal(t, RemoteArtifactDeliveryAuditFailed, event.State)
			}

			remoteConflict.Store(false)
			source.set(artifact)
			remoteArtifactDeliveryTestFlush(t, delivery)
			require.Equal(t, int32(1), calls.Load())
			require.Equal(t, content, <-published)
			status, err := receipts.store.targetStatus(t.Context(), artifact.FileName(), targets.entries[0])
			require.NoError(t, err)
			require.Equal(t, remoteArtifactReceiptTargetAcknowledged, status)
		})
	}
}
