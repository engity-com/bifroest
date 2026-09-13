package service

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

var _ = audit.RegisterRemoteTarget(
	func() configuration.AuditlogTargetV { return &serviceRemoteDeliveryTestConfiguration{} },
	func(_ context.Context, _ audit.RemoteTargetScope, conf *serviceRemoteDeliveryTestConfiguration) (audit.RemoteTarget, audit.RemoteTargetSettings, error) {
		return conf.target, audit.RemoteTargetSettings{DestinationIdentity: "service-test-destination", PublishAttemptTimeout: time.Minute}, nil
	},
)

type serviceRemoteDeliveryTestConfiguration struct {
	target audit.RemoteTarget
}

func (this *serviceRemoteDeliveryTestConfiguration) SetDefaults() error { return nil }
func (this *serviceRemoteDeliveryTestConfiguration) Trim() error        { return this.Validate() }
func (this *serviceRemoteDeliveryTestConfiguration) Validate() error {
	if this == nil || this.target == nil {
		return fmt.Errorf("missing service delivery test target")
	}
	return nil
}
func (*serviceRemoteDeliveryTestConfiguration) UnmarshalYAML(*yaml.Node) error { return nil }
func (*serviceRemoteDeliveryTestConfiguration) IsEqualTo(other any) bool {
	_, ok := other.(*serviceRemoteDeliveryTestConfiguration)
	return ok
}
func (*serviceRemoteDeliveryTestConfiguration) Types() []string {
	return []string{"service-runtime-test"}
}
func (*serviceRemoteDeliveryTestConfiguration) FeatureFlags() []string { return nil }

type serviceRemoteDeliveryTestTarget struct {
	published chan uint64
	closed    atomic.Bool
}

func (this *serviceRemoteDeliveryTestTarget) Publish(_ context.Context, segment audit.SealedSegment) error {
	this.published <- segment.Sequence()
	return nil
}

func (this *serviceRemoteDeliveryTestTarget) Close() error {
	this.closed.Store(true)
	return nil
}

func TestServiceShutdownSealsAndFlushesAuditTail(t *testing.T) {
	directory := t.TempDir()
	target := &serviceRemoteDeliveryTestTarget{published: make(chan uint64, 1)}
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		auditlog := &conf.Auditlogs[0]
		auditlog.Enabled = true
		auditlog.IdentityFile = filepath.Join(directory, "auditlog-key")
		auditlog.Journal.Directory = filepath.Join(directory, "auditlog")
		auditlog.Targets = configuration.AuditlogTargets{{
			Name: "archive",
			V:    &serviceRemoteDeliveryTestConfiguration{target: target},
		}}
	})
	recorder := server.service.auditRecorders[configuration.DefaultAuditlogName]
	require.NoError(t, recorder.Record(context.Background(), audit.Event{Name: "test.shutdown"}))
	require.NoError(t, server.stop())

	select {
	case sequence := <-target.published:
		require.Equal(t, uint64(1), sequence)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not flush the sealed audit tail")
	}
	require.True(t, target.closed.Load())
}
