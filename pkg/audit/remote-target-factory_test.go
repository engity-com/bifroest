package audit

import (
	"context"
	goerrors "errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/configuration"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
)

var _ = RegisterRemoteTarget(
	func() configuration.AuditlogTargetV { return &remoteTargetTestConfiguration{} },
	func(ctx context.Context, scope RemoteTargetScope, conf *remoteTargetTestConfiguration) (RemoteTarget, RemoteTargetSettings, error) {
		target, err := conf.create(ctx, scope)
		if conf.omitDestinationIdentity {
			return target, RemoteTargetSettings{PublishAttemptTimeout: time.Minute}, err
		}
		identity := conf.destinationIdentity
		if identity == "" {
			identity = remoteTargetTestDestinationIdentity
		}
		timeout := conf.publishAttemptTimeout
		if timeout == 0 {
			timeout = time.Minute
		}
		return target, RemoteTargetSettings{DestinationIdentity: identity, PublishAttemptTimeout: timeout}, err
	},
)

const remoteTargetTestDestinationIdentity RemoteTargetDestinationIdentity = "runtime-test-destination"

type remoteTargetTestConfiguration struct {
	create                  func(context.Context, RemoteTargetScope) (RemoteTarget, error)
	destinationIdentity     RemoteTargetDestinationIdentity
	publishAttemptTimeout   time.Duration
	omitDestinationIdentity bool
}

func (this *remoteTargetTestConfiguration) SetDefaults() error { return nil }
func (this *remoteTargetTestConfiguration) Trim() error        { return this.Validate() }
func (this *remoteTargetTestConfiguration) Validate() error {
	if this == nil || this.create == nil {
		return fmt.Errorf("missing test factory")
	}
	return nil
}
func (this *remoteTargetTestConfiguration) UnmarshalYAML(*yaml.Node) error { return nil }
func (this *remoteTargetTestConfiguration) IsEqualTo(other any) bool {
	_, ok := other.(*remoteTargetTestConfiguration)
	return ok
}
func (this *remoteTargetTestConfiguration) Types() []string        { return []string{"runtime-test"} }
func (this *remoteTargetTestConfiguration) FeatureFlags() []string { return nil }

type unregisteredRemoteTargetTestConfiguration struct{}

func (this *unregisteredRemoteTargetTestConfiguration) SetDefaults() error { return nil }
func (this *unregisteredRemoteTargetTestConfiguration) Trim() error        { return nil }
func (this *unregisteredRemoteTargetTestConfiguration) Validate() error    { return nil }
func (this *unregisteredRemoteTargetTestConfiguration) UnmarshalYAML(*yaml.Node) error {
	return nil
}
func (this *unregisteredRemoteTargetTestConfiguration) IsEqualTo(other any) bool { return false }
func (this *unregisteredRemoteTargetTestConfiguration) Types() []string {
	return []string{"unregistered"}
}
func (this *unregisteredRemoteTargetTestConfiguration) FeatureFlags() []string { return nil }

type remoteTargetTestInstance struct {
	publish func(context.Context, SealedSegment) error
	close   func() error
}

func (this *remoteTargetTestInstance) Publish(ctx context.Context, segment SealedSegment) error {
	if this.publish != nil {
		return this.publish(ctx, segment)
	}
	return nil
}
func (this *remoteTargetTestInstance) Close() error {
	if this.close != nil {
		return this.close()
	}
	return nil
}

func TestNewRemoteTargetPassesContextAndScope(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "expected")
	expected := &remoteTargetTestInstance{}
	conf := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(actualContext context.Context, scope RemoteTargetScope) (RemoteTarget, error) {
			require.Equal(t, "expected", actualContext.Value(contextKey{}))
			require.Equal(t, RemoteTargetScope{Auditlog: "security", Target: "archive"}, scope)
			return expected, nil
		}},
	}
	actual, err := NewRemoteTarget(ctx, "security", &conf)
	require.NoError(t, err)
	validating, ok := actual.(*validatingRemoteTarget)
	require.True(t, ok)
	require.Same(t, expected, validating.target)
}

func TestNewRemoteTargetValidatesEveryPublishedSegment(t *testing.T) {
	published := 0
	conf := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return &remoteTargetTestInstance{publish: func(context.Context, SealedSegment) error {
				published++
				return nil
			}}, nil
		}},
	}
	target, err := NewRemoteTarget(context.Background(), "security", &conf)
	require.NoError(t, err)
	require.NoError(t, target.Publish(context.Background(), validRemoteTargetTestSegment()))
	require.Equal(t, 1, published)
	require.Error(t, target.Publish(context.Background(), SealedSegment{}))
	require.Equal(t, 1, published)
}

func TestNewRemoteTargetRejectsInvalidFactories(t *testing.T) {
	unsupported := configuration.AuditlogTarget{Name: "archive", V: &unregisteredRemoteTargetTestConfiguration{}}
	_, err := NewRemoteTarget(context.Background(), "security", &unsupported)
	require.ErrorContains(t, err, "unsupported configuration type")
	require.True(t, bferrors.Config.IsErr(err))

	typedNil := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return (*remoteTargetTestInstance)(nil), nil
		}},
	}
	_, err = NewRemoteTarget(context.Background(), "security", &typedNil)
	require.ErrorContains(t, err, "factory returned nil")
	require.True(t, bferrors.System.IsErr(err))

	configurationFailure := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			return nil, bferrors.Config.Newf("bad endpoint")
		}},
	}
	_, err = NewRemoteTarget(context.Background(), "security", &configurationFailure)
	require.ErrorContains(t, err, "bad endpoint")
	require.True(t, bferrors.Config.IsErr(err))
}

func TestNewRemoteTargetRequiresCustomDestinationIdentity(t *testing.T) {
	closed := false
	conf := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{
			omitDestinationIdentity: true,
			create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
				return &remoteTargetTestInstance{close: func() error { closed = true; return nil }}, nil
			},
		},
	}
	target, err := NewRemoteTarget(context.Background(), "security", &conf)
	require.Nil(t, target)
	require.ErrorContains(t, err, "empty destination identity")
	require.True(t, bferrors.Config.IsErr(err))
	require.True(t, closed)
}

func TestNewRemoteTargetUsesCustomDestinationIdentityForFingerprint(t *testing.T) {
	newEntry := func(identity RemoteTargetDestinationIdentity, timeout time.Duration) remoteTargetEntry {
		conf := configuration.AuditlogTarget{
			Name: "archive",
			V: &remoteTargetTestConfiguration{
				destinationIdentity:   identity,
				publishAttemptTimeout: timeout,
				create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
					return &remoteTargetTestInstance{}, nil
				},
			},
		}
		entry, err := newRemoteTargetEntry(context.Background(), "security", &conf)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, entry.target.Close()) })
		return entry
	}

	first := newEntry("https://first.example.invalid/archive", 17*time.Second)
	second := newEntry("https://second.example.invalid/archive", 17*time.Second)
	rotatedTimeout := newEntry("https://first.example.invalid/archive", 30*time.Second)
	require.Equal(t, 17*time.Second, first.publishAttemptTimeout)
	require.NotEqual(t, first.destinationFingerprint, second.destinationFingerprint)
	require.Equal(t, first.destinationFingerprint, rotatedTimeout.destinationFingerprint)
}

func TestNewRemoteTargetRequiresPositiveCustomPublishAttemptTimeout(t *testing.T) {
	conf := configuration.AuditlogTarget{
		Name: "archive",
		V: &remoteTargetTestConfiguration{
			publishAttemptTimeout: -time.Second,
			create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
				return &remoteTargetTestInstance{}, nil
			},
		},
	}
	target, err := NewRemoteTarget(context.Background(), "security", &conf)
	require.Nil(t, target)
	require.ErrorContains(t, err, "non-positive publish-attempt timeout")
}

func TestRemoteTargetsLifecycleOrderAndIdempotence(t *testing.T) {
	var mutex sync.Mutex
	var events []string
	appendEvent := func(event string) {
		mutex.Lock()
		defer mutex.Unlock()
		events = append(events, event)
	}
	configurations := configuration.AuditlogTargets{
		remoteTargetTestEntry("first", func() error { appendEvent("close:first"); return goerrors.New("first close failed") }, appendEvent),
		remoteTargetTestEntry("second", func() error { appendEvent("close:second"); return goerrors.New("second close failed") }, appendEvent),
	}
	targets, err := NewRemoteTargets(context.Background(), "security", configurations)
	require.NoError(t, err)
	require.Len(t, targets.entries, 2)
	err = targets.Close()
	require.ErrorContains(t, err, "first close failed")
	require.ErrorContains(t, err, "second close failed")
	require.Equal(t, []string{"init:first", "init:second", "close:second", "close:first"}, events)
	require.Equal(t, err, targets.Close())
	require.Len(t, events, 4)
}

func TestRemoteTargetsRollBackInReverseOrder(t *testing.T) {
	var events []string
	configurations := configuration.AuditlogTargets{
		remoteTargetTestEntry("first", func() error { events = append(events, "close:first"); return nil }, func(event string) { events = append(events, event) }),
		remoteTargetTestEntry("second", func() error { events = append(events, "close:second"); return goerrors.New("rollback close failed") }, func(event string) { events = append(events, event) }),
		{
			Name: "third",
			V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
				events = append(events, "init:third")
				return nil, bferrors.Config.Newf("initialization failed")
			}},
		},
	}
	targets, err := NewRemoteTargets(context.Background(), "security", configurations)
	require.Nil(t, targets)
	require.ErrorContains(t, err, "initialization failed")
	require.ErrorContains(t, err, "rollback close failed")
	require.True(t, bferrors.Config.IsErr(err))
	require.True(t, bferrors.System.IsErr(err))
	require.Equal(t, []string{"init:first", "init:second", "init:third", "close:second", "close:first"}, events)
}

func TestNewRemoteTargetsAcceptsEmptySet(t *testing.T) {
	targets, err := NewRemoteTargets(nil, "security", nil)
	require.NoError(t, err)
	require.NotNil(t, targets)
	require.NoError(t, targets.Close())
}

func TestRegisterRemoteTargetRejectsInterfaceConfiguration(t *testing.T) {
	require.Panics(t, func() {
		RegisterRemoteTarget[configuration.AuditlogTargetV](
			func() configuration.AuditlogTargetV { return &remoteTargetTestConfiguration{} },
			func(context.Context, RemoteTargetScope, configuration.AuditlogTargetV) (RemoteTarget, RemoteTargetSettings, error) {
				return &remoteTargetTestInstance{}, RemoteTargetSettings{DestinationIdentity: "destination", PublishAttemptTimeout: time.Minute}, nil
			},
		)
	})
}

func remoteTargetTestEntry(name configuration.AuditlogTargetName, close func() error, event func(string)) configuration.AuditlogTarget {
	return configuration.AuditlogTarget{
		Name: name,
		V: &remoteTargetTestConfiguration{create: func(context.Context, RemoteTargetScope) (RemoteTarget, error) {
			event("init:" + name.String())
			return &remoteTargetTestInstance{close: close}, nil
		}},
	}
}
