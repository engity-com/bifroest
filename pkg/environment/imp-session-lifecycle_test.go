package environment

import (
	"context"
	"errors"
	gonet "net"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
}

type lifecycleStoredSession struct {
	session.Session
	id session.Id
}

func (s *lifecycleStoredSession) Id() session.Id { return s.id }

type lifecycleReverseEnvironment interface {
	ListenReverseTCP(context.Context, string, uint16) (gonet.Listener, error)
}

func (i *lifecycleImp) Open(ctx context.Context, _ imp.Ref) (imp.Session, error) {
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
			cancel()
			require.NoError(t, opened.ctx.Err())
			second, err := reuse()
			require.NoError(t, err)
			require.Same(t, env, second)
			listener, err := second.(lifecycleReverseEnvironment).ListenReverseTCP(context.Background(), "127.0.0.1", 0)
			require.NoError(t, err)
			closed := listener.(*lifecycleListener).closed
			require.NoError(t, env.Close())
			require.Equal(t, 0, opened.closes())
			require.NoError(t, opened.ctx.Err())
			require.True(t, cached())
			select {
			case <-closed:
				t.Fatal("listener closed while another owner still uses the environment")
			default:
			}
			require.NoError(t, second.Close())
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
				DockerLabelPortForwardingAllowed: "true",
			}, Ports: []types.Port{{PrivatePort: imp.ServicePort, PublicPort: 12345, Type: "tcp"}}}
			env, err := repo.new(ctx, container, log.GetLogger("test"))
			if err == nil {
				repo.activeInstances.Store(id, env)
			}
			return env, func() (Environment, error) {
				return repo.FindBySession(context.Background(), &lifecycleStoredSession{id: id}, nil)
			}, func() bool { _, ok := repo.activeInstances.Load(id); return ok }, err
		}},
		{"kubernetes", func(ctx context.Context, i imp.Imp) (Environment, func() (Environment, error), func() bool, error) {
			id := session.MustNewId()
			repo := &KubernetesRepository{flow: configuration.FlowName("test"), imp: i}
			pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", Labels: map[string]string{
				KubernetesLabelFlow: "test", KubernetesLabelSessionId: id.String(),
			}, Annotations: map[string]string{
				KubernetesAnnotationCreatedRemoteHost: "127.0.0.1",
				KubernetesAnnotationShellCommand:      `["sh"]`, KubernetesAnnotationExecCommand: `["sh"]`,
				KubernetesAnnotationPortForwardingAllowed: "true",
			}}}
			env, err := repo.new(ctx, pod, log.GetLogger("test"))
			if err == nil {
				repo.activeInstances.Store(id, env)
			}
			return env, func() (Environment, error) {
				return repo.FindBySession(context.Background(), &lifecycleStoredSession{id: id}, nil)
			}, func() bool { _, ok := repo.activeInstances.Load(id); return ok }, err
		}},
	}
}
