package environment

import (
	"context"
	"errors"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type lifecycleImp struct {
	imp.Imp
	open func(context.Context) imp.Session
	ref  imp.Ref
}

type lifecycleStoredSession struct {
	session.Session
	id session.Id
}

func (s *lifecycleStoredSession) Id() session.Id               { return s.id }
func (s *lifecycleStoredSession) Flow() configuration.FlowName { return "test" }

type lifecycleReverseEnvironment interface {
	ListenReverseTCP(context.Context, string, uint16) (gonet.Listener, error)
}

func (i *lifecycleImp) Open(ctx context.Context, ref imp.Ref) (imp.Session, error) {
	i.ref = ref
	return i.open(ctx), nil
}

type lifecycleSession struct {
	imp.ExecutionSession
	ctx        context.Context
	cancel     context.CancelFunc
	pingErr    error
	getErr     error
	closeMu    sync.Mutex
	closeCount int
}

func (s *lifecycleSession) Ping(context.Context, connection.Id) error { return s.pingErr }
func (s *lifecycleSession) GetEnvironment(context.Context, connection.Id) (sys.EnvVars, error) {
	return sys.EnvVars{}, s.getErr
}
func (s *lifecycleSession) ListenReverseTCP(ctx context.Context, _ connection.Id, _ string, _ uint16) (gonet.Listener, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	listener := &lifecycleListener{closed: make(chan struct{})}
	context.AfterFunc(s.ctx, func() { _ = listener.Close() })
	context.AfterFunc(ctx, func() { _ = listener.Close() })
	return listener, nil
}

type lifecycleListener struct {
	once   sync.Once
	closed chan struct{}
}

func (l *lifecycleListener) Accept() (gonet.Conn, error) {
	<-l.closed
	return nil, gonet.ErrClosed
}
func (l *lifecycleListener) Addr() gonet.Addr { return nil }
func (l *lifecycleListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (s *lifecycleSession) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.closeCount++
	s.cancel()
	return nil
}

func (s *lifecycleSession) closes() int {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closeCount
}

func TestContainerImpSessionOutlivesInitialRequest(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
				sessionCtx, cancel := context.WithCancel(ctx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel}
				return opened
			}}
			initialCtx, cancel := context.WithCancel(context.Background())
			env, reuse, cached, err := tc.new(initialCtx, i)
			require.NoError(t, err)
			require.Same(t, env.(*containerLease).Environment, i.ref)
			cancel()
			require.NoError(t, opened.ctx.Err())
			second, err := reuse()
			require.NoError(t, err)
			require.NotSame(t, env, second)
			require.Same(t, env.(*containerLease).Environment, second.(*containerLease).Environment)
			_, reverse := second.(ReverseTCPListener)
			require.True(t, reverse)
			_, subsystem := second.(SubsystemRunner)
			require.False(t, subsystem)
			_, policy := second.(ReversePortForwardingPolicy)
			require.False(t, policy)
			listener, err := second.(lifecycleReverseEnvironment).ListenReverseTCP(context.Background(), "127.0.0.1", 0)
			require.NoError(t, err)
			closed := listener.(*lifecycleListener).closed
			require.NoError(t, env.Close())
			require.NoError(t, env.Close())
			require.Equal(t, 0, opened.closes())
			require.NoError(t, opened.ctx.Err())
			require.True(t, cached())
			select {
			case <-closed:
				t.Fatal("listener closed while another owner still uses the environment")
			default:
			}
			third, err := reuse()
			require.NoError(t, err)
			require.NotSame(t, second, third)
			require.NoError(t, second.Close())
			require.NoError(t, second.Close())
			require.Equal(t, 0, opened.closes())
			require.NoError(t, third.Close())
			require.Equal(t, 1, opened.closes())
			require.ErrorIs(t, opened.ctx.Err(), context.Canceled)
			require.Eventually(t, func() bool {
				select {
				case <-closed:
					return true
				default:
					return false
				}
			}, time.Second, time.Millisecond)
			require.False(t, cached())
			require.NoError(t, env.Close())
			require.Equal(t, 1, opened.closes())
		})
	}
}

type lifecycleDockerAPIClient struct {
	client.APIClient
	removes int
}

func (c *lifecycleDockerAPIClient) ContainerRemove(context.Context, string, container.RemoveOptions) error {
	c.removes++
	return nil
}

func TestDockerLeaseDisposeInvalidatesCacheWithActiveOwner(t *testing.T) {
	var opened *lifecycleSession
	i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
		sessionCtx, cancel := context.WithCancel(ctx)
		opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel}
		return opened
	}}
	tc := containerLifecycleCases()[0]
	first, reuse, cached, err := tc.new(context.Background(), i)
	require.NoError(t, err)
	second, err := reuse()
	require.NoError(t, err)
	raw := first.(*containerLease).Environment.(*docker)
	api := &lifecycleDockerAPIClient{}
	raw.repository.apiClient = api

	removed, err := first.Dispose(context.Background())
	require.NoError(t, err)
	require.True(t, removed)
	require.Equal(t, 1, api.removes)
	require.False(t, cached())
	require.Equal(t, int32(1), raw.owners.Load())
	require.Equal(t, 0, opened.closes())
	removed, err = first.Dispose(context.Background())
	require.False(t, removed)
	require.ErrorContains(t, err, "lease already closed")
	require.NoError(t, first.Close())
	require.Equal(t, 1, api.removes)
	require.NoError(t, second.Close())
	require.Equal(t, 1, opened.closes())
	require.Equal(t, int32(0), raw.owners.Load())
}

func TestContainerLeaseConcurrentClose(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
				sessionCtx, cancel := context.WithCancel(ctx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel}
				return opened
			}}
			first, reuse, cached, err := tc.new(context.Background(), i)
			require.NoError(t, err)
			second, err := reuse()
			require.NoError(t, err)
			var wg sync.WaitGroup
			errs := make(chan error, 100)
			for n := 0; n < 100; n++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- first.Close()
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}
			require.Equal(t, int32(1), containerLeaseOwners(first))
			require.Equal(t, 0, opened.closes())
			require.True(t, cached())
			require.NoError(t, second.Close())
			require.Equal(t, int32(0), containerLeaseOwners(first))
			require.Equal(t, 1, opened.closes())
			require.False(t, cached())
		})
	}
}

func containerLeaseOwners(env Environment) int32 {
	switch raw := env.(*containerLease).Environment.(type) {
	case *docker:
		return raw.owners.Load()
	case *kubernetes:
		return raw.owners.Load()
	default:
		panic("unexpected environment")
	}
}

func TestContainerLeaseCloseDoesNotEvictReplacement(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
				sessionCtx, cancel := context.WithCancel(ctx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel}
				return opened
			}}
			old, _, _, err := tc.new(context.Background(), i)
			require.NoError(t, err)
			lease := old.(*containerLease)
			switch raw := lease.Environment.(type) {
			case *docker:
				replacement := &docker{repository: raw.repository, sessionId: raw.sessionId}
				replacement.owners.Add(1)
				raw.repository.activeInstances.Store(raw.sessionId, replacement)
				require.NoError(t, old.Close())
				cached, ok := raw.repository.activeInstances.Load(raw.sessionId)
				require.True(t, ok)
				require.Same(t, replacement, cached)
				raw.repository.activeInstances.Delete(raw.sessionId)
			case *kubernetes:
				replacement := &kubernetes{repository: raw.repository, sessionId: raw.sessionId}
				replacement.owners.Add(1)
				raw.repository.activeInstances.Store(raw.sessionId, replacement)
				require.NoError(t, old.Close())
				cached, ok := raw.repository.activeInstances.Load(raw.sessionId)
				require.True(t, ok)
				require.Same(t, replacement, cached)
				raw.repository.activeInstances.Delete(raw.sessionId)
			}
			require.Equal(t, 1, opened.closes())
			require.Equal(t, int32(0), containerLeaseOwners(old))
		})
	}
}

type lifecycleDisposableEnvironment struct {
	Environment
	closes   int
	disposes int
}

func (e *lifecycleDisposableEnvironment) Close() error {
	e.closes++
	return nil
}

func (e *lifecycleDisposableEnvironment) Dispose(context.Context) (bool, error) {
	e.disposes++
	return true, nil
}

func TestContainerLeaseDisposeAndClose(t *testing.T) {
	ctx := context.Background()
	for _, disposeFirst := range []bool{true, false} {
		raw := &lifecycleDisposableEnvironment{}
		lease := &containerLease{Environment: raw}
		if disposeFirst {
			removed, err := lease.Dispose(ctx)
			require.NoError(t, err)
			require.True(t, removed)
			require.NoError(t, lease.Close())
		} else {
			require.NoError(t, lease.Close())
			removed, err := lease.Dispose(ctx)
			require.False(t, removed)
			require.ErrorContains(t, err, "lease already closed")
		}
		removed, err := lease.Dispose(ctx)
		require.False(t, removed)
		require.ErrorContains(t, err, "lease already closed")
		require.NoError(t, lease.Close())
		if disposeFirst {
			require.Equal(t, 1, raw.disposes)
			require.Zero(t, raw.closes)
		} else {
			require.Zero(t, raw.disposes)
			require.Equal(t, 1, raw.closes)
		}
	}
}

func TestContainerLeaseConcurrentDisposeAndClose(t *testing.T) {
	raw := &lifecycleDisposableEnvironment{}
	lease := &containerLease{Environment: raw}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 100; n++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = lease.Close()
		}()
		go func() {
			defer wg.Done()
			<-start
			_, _ = lease.Dispose(context.Background())
		}()
	}
	close(start)
	wg.Wait()
	require.Equal(t, 1, raw.closes+raw.disposes)
	if raw.closes == 1 {
		require.Zero(t, raw.disposes)
	} else {
		require.Equal(t, 1, raw.disposes)
	}
}

func TestContainerImpSessionClosesWithOnlyOwner(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
				sessionCtx, cancel := context.WithCancel(ctx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel}
				return opened
			}}
			env, _, cached, err := tc.new(context.Background(), i)
			require.NoError(t, err)
			listener, err := env.(lifecycleReverseEnvironment).ListenReverseTCP(context.Background(), "127.0.0.1", 0)
			require.NoError(t, err)
			require.NoError(t, env.Close())
			require.Equal(t, 1, opened.closes())
			require.ErrorIs(t, opened.ctx.Err(), context.Canceled)
			require.Eventually(t, func() bool {
				select {
				case <-listener.(*lifecycleListener).closed:
					return true
				default:
					return false
				}
			}, time.Second, time.Millisecond)
			require.False(t, cached())
		})
	}
}

func TestContainerImpSessionClosesOnReadinessFailure(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			want := errors.New("readiness failed")
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(ctx context.Context) imp.Session {
				sessionCtx, cancel := context.WithCancel(ctx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: cancel, pingErr: want, getErr: want}
				return opened
			}}
			_, _, _, err := tc.new(context.Background(), i)
			require.ErrorIs(t, err, want)
			require.Equal(t, 1, opened.closes())
			require.ErrorIs(t, opened.ctx.Err(), context.Canceled)
		})
	}
}

func TestContainerImpSessionClosesWhenInitialRequestIsCanceled(t *testing.T) {
	for _, tc := range containerLifecycleCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var opened *lifecycleSession
			i := &lifecycleImp{open: func(openCtx context.Context) imp.Session {
				sessionCtx, closeSession := context.WithCancel(openCtx)
				opened = &lifecycleSession{ctx: sessionCtx, cancel: closeSession}
				cancel()
				return opened
			}}
			_, _, _, err := tc.new(ctx, i)
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, 1, opened.closes())
			require.ErrorIs(t, opened.ctx.Err(), context.Canceled)
		})
	}
}

func containerLifecycleCases() []struct {
	name string
	new  func(context.Context, imp.Imp) (Environment, func() (Environment, error), func() bool, error)
} {
	return []struct {
		name string
		new  func(context.Context, imp.Imp) (Environment, func() (Environment, error), func() bool, error)
	}{
		{"docker", func(ctx context.Context, i imp.Imp) (Environment, func() (Environment, error), func() bool, error) {
			id := session.MustNewId()
			repo := &DockerRepository{flow: configuration.FlowName("test"), conf: &configuration.EnvironmentDocker{ImpPublishHost: net.MustNewHost("127.0.0.1")}, imp: i}
			container := &types.Container{ID: "test", Labels: map[string]string{
				DockerLabelFlow: "test", DockerLabelSessionId: id.String(), DockerLabelCreatedRemoteHost: "127.0.0.1",
				DockerLabelShellCommand: `["sh"]`, DockerLabelExecCommand: `["sh"]`,
				DockerLabelExecutionLifecycle: executionLifecycleCapability, DockerLabelImpProtocolRevision: "2",
				DockerLabelPortForwardingAllowed: "true",
			}, Ports: []types.Port{{PrivatePort: imp.ServicePort, PublicPort: 12345, Type: "tcp"}}}
			env, err := repo.new(ctx, container, log.GetLogger("test"))
			if err != nil {
				return nil, nil, nil, err
			}
			repo.activeInstances.Store(id, env)
			return &containerLease{Environment: env, ReverseTCPListener: env}, func() (Environment, error) {
				return repo.FindBySession(context.Background(), &lifecycleStoredSession{id: id}, nil)
			}, func() bool { _, ok := repo.activeInstances.Load(id); return ok }, err
		}},
		{"kubernetes", func(ctx context.Context, i imp.Imp) (Environment, func() (Environment, error), func() bool, error) {
			id := session.MustNewId()
			repo := &KubernetesRepository{flow: configuration.FlowName("test"), imp: i, conf: &configuration.EnvironmentKubernetes{}}
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Labels: map[string]string{
				KubernetesLabelFlow: "test", KubernetesLabelSessionId: id.String(),
			}, Annotations: map[string]string{
				KubernetesAnnotationCreatedRemoteHost: "127.0.0.1",
				KubernetesAnnotationShellCommand:      `["sh"]`, KubernetesAnnotationExecCommand: `["sh"]`,
				KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability, KubernetesAnnotationImpProtocolRevision: "2",
				KubernetesAnnotationPortForwardingAllowed: "true",
			}}}
			repo.client = &protocolKubernetesClient{clientSet: fake.NewSimpleClientset(pod)}
			env, err := repo.new(ctx, pod, log.GetLogger("test"))
			if err != nil {
				return nil, nil, nil, err
			}
			repo.activeInstances.Store(id, env)
			return &containerLease{Environment: env, ReverseTCPListener: env}, func() (Environment, error) {
				return repo.FindBySession(context.Background(), &lifecycleStoredSession{id: id}, nil)
			}, func() bool { _, ok := repo.activeInstances.Load(id); return ok }, err
		}},
	}
}
