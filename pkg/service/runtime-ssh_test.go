package service

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func runtimeSshListener(t *testing.T, svc *service) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		svc.handlerLifecycle().stop()
		cancel()
		select {
		case err := <-done:
			require.False(t, svc.isProblematicError(err), "%v", err)
		case <-time.After(5 * time.Second):
			t.Error("SSH server did not stop")
		}
		require.True(t, svc.handlerLifecycle().wait(5*time.Second))
	})
	return listener.Addr().String()
}

func runtimeSshConfig(svc *service, password string) *gossh.ClientConfig {
	return &gossh.ClientConfig{
		User: "alice", Auth: []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.FixedHostKey(svc.server.HostSigners[0].PublicKey()), Timeout: 3 * time.Second,
	}
}

func runtimeSshDial(t *testing.T, svc *service, address, password string) *gossh.Client {
	t.Helper()
	client, err := gossh.Dial("tcp", address, runtimeSshConfig(svc, password))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func runtimeSshConnection(t *testing.T, svc *service, client *gossh.Client) *connection {
	t.Helper()
	id := hex.EncodeToString(client.SessionID())
	for _, candidate := range svc.runtime.allConnections() {
		if conn, ok := candidate.(*connection); ok && conn.context.SessionID() == id {
			return conn
		}
	}
	t.Fatal("authenticated SSH connection is missing from runtime registry")
	return nil
}

func runtimeSshSession(conn *connection) session.Session {
	return conn.context.Value(authorizationCtxKey).(authorization.Authorization).FindSession()
}

func runtimeSshRun(t *testing.T, client *gossh.Client, exit int) {
	t.Helper()
	channel, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	err = channel.Run("test")
	if exit == 0 {
		require.NoError(t, err)
	} else {
		var status *gossh.ExitError
		require.ErrorAs(t, err, &status)
		require.Equal(t, exit, status.ExitStatus())
	}
}

func runtimeSshCandidate(t *testing.T, svc *service, configure func(*configuration.Configuration)) *service {
	t.Helper()
	conf := svc.generation.snapshot.Configuration()
	configure(&conf)
	candidate, err := svc.prepareGeneration(t.Context(), conf)
	require.NoError(t, err)
	t.Cleanup(func() {
		if svc.runtime.discard(candidate.generation) {
			<-candidate.generationClosed
		}
	})
	return candidate
}

func runtimeSshActivate(t *testing.T, svc *service, candidate *service) *runtimeActivation {
	t.Helper()
	activation, err := svc.runtime.activate(t.Context(), candidate.generation)
	require.NoError(t, err)
	require.NoError(t, activation.closeConnections())
	return activation
}

func TestRuntimeSshDispatchKeepsOldChannelsAndUsesNewCredentialsAndEnvironment(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	address := runtimeSshListener(t, svc)
	old := runtimeSshDial(t, svc, address, "correct")
	oldConn := runtimeSshConnection(t, svc, old)
	require.Same(t, svc, oldConn.service)
	oldSession := runtimeSshSession(oldConn)
	runtimeSshRun(t, old, 0)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(17)
	})
	activation := runtimeSshActivate(t, svc, next)
	require.Empty(t, activation.connections)
	runtimeSshRun(t, old, 0) // A new channel on the already authenticated connection.
	denied, err := gossh.Dial("tcp", address, runtimeSshConfig(svc, "correct"))
	if denied != nil {
		_ = denied.Close()
	}
	require.Error(t, err)
	fresh := runtimeSshDial(t, svc, address, "changed")
	freshConn := runtimeSshConnection(t, svc, fresh)
	require.Same(t, next, freshConn.service)
	require.NotEqual(t, oldSession.Id(), runtimeSshSession(freshConn).Id())
	require.Same(t, svc.generation, svc.runtime.sessionOwner(oldSession))
	runtimeSshRun(t, fresh, 17)
	runtimeSshRun(t, old, 0)
}

func TestRuntimeSshDispatchReusesSessionOnlyAfterNewAuthentication(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	address := runtimeSshListener(t, svc)
	old := runtimeSshDial(t, svc, address, "correct")
	original := runtimeSshSession(runtimeSshConnection(t, svc, old))
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
		conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
	})
	runtimeSshActivate(t, svc, next)
	fresh := runtimeSshDial(t, svc, address, "changed")
	require.Equal(t, original.Id(), runtimeSshSession(runtimeSshConnection(t, svc, fresh)).Id())
	require.Same(t, svc.generation, svc.runtime.sessionOwner(original))
	runtimeSshRun(t, old, 0)
	runtimeSshRun(t, fresh, 0)
}

func TestRuntimeSshDispatchPinsGenerationBeforeClientAuthentication(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(map[bool]string{false: "modified", true: "deleted"}[deleted], func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			address := runtimeSshListener(t, svc)
			wire, err := net.DialTimeout("tcp", address, 3*time.Second)
			require.NoError(t, err)
			defer func() { _ = wire.Close() }()
			require.NoError(t, wire.SetDeadline(time.Now().Add(5*time.Second)))
			reader := bufio.NewReader(wire)
			banner, err := reader.ReadString('\n')
			require.NoError(t, err)
			require.True(t, strings.HasPrefix(banner, "SSH-2.0-"))
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) {
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
				if deleted {
					conf.Flows[0].Name = "replacement"
				}
			})
			runtimeSshActivate(t, svc, next)
			// Restore the consumed banner for the real SSH handshake.
			conn := &runtimeSshBufferedConn{Conn: wire, reader: io.MultiReader(strings.NewReader(banner), reader)}
			cc, channels, requests, err := gossh.NewClientConn(conn, address, runtimeSshConfig(svc, "correct"))
			if deleted {
				if cc != nil {
					_ = cc.Close()
				}
				require.Error(t, err, "deleted flow must not finish an old pending authentication")
			} else {
				require.NoError(t, err, "an admitted SSH handshake keeps its original authentication rules")
				client := gossh.NewClient(cc, channels, requests)
				defer func() { _ = client.Close() }()
				require.Same(t, svc, runtimeSshConnection(t, svc, client).service)
				runtimeSshRun(t, client, 0)
			}
		})
	}
}

// Prepend bytes already consumed while synchronizing a server-first handshake.
type runtimeSshBufferedConn struct {
	net.Conn
	reader io.Reader
}

func (this *runtimeSshBufferedConn) Read(target []byte) (int, error) {
	return this.reader.Read(target)
}

func TestRuntimeSshDispatchDeletionClosesAllGenerationsAndRecreationCannotReviveThem(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	address := runtimeSshListener(t, svc)
	old := runtimeSshDial(t, svc, address, "correct")
	original := runtimeSshSession(runtimeSshConnection(t, svc, old))
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "changed" })
	runtimeSshActivate(t, svc, next)
	second := runtimeSshDial(t, svc, address, "correct")
	removed := runtimeSshCandidate(t, next, func(conf *configuration.Configuration) { conf.Flows[0].Name = "replacement" })
	activation := runtimeSshActivate(t, svc, removed)
	require.Len(t, activation.connections, 2)
	for _, client := range []*gossh.Client{old, second} {
		done := make(chan error, 1)
		go func() { done <- client.Wait() }()
		select {
		case _ = <-done: // Revocation intentionally closes the socket.
		case <-time.After(3 * time.Second):
			t.Fatal("deleted flow still has an active SSH connection")
		}
		_, err := client.NewSession()
		require.Error(t, err)
	}
	recreated := runtimeSshCandidate(t, removed, func(conf *configuration.Configuration) { conf.Flows[0].Name = original.Flow() })
	runtimeSshActivate(t, svc, recreated)
	fresh := runtimeSshDial(t, svc, address, "correct")
	require.NotEqual(t, original.Id(), runtimeSshSession(runtimeSshConnection(t, svc, fresh)).Id())
	require.False(t, svc.runtime.sessionCompatible(recreated.generation, original))
}

func TestRuntimeSshDispatchDoesNotResetServeChannelBudget(t *testing.T) {
	svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) { conf.Ssh.MaxChannels = 1 })
	address := runtimeSshListener(t, svc)
	old := runtimeSshDial(t, svc, address, "correct")
	held, err := old.NewSession()
	require.NoError(t, err)
	defer func() { _ = held.Close() }()
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "changed" })
	runtimeSshActivate(t, svc, next)
	fresh := runtimeSshDial(t, svc, address, "correct")
	channel, err := fresh.NewSession()
	if channel != nil {
		_ = channel.Close()
	}
	var rejected *gossh.OpenChannelError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, gossh.ResourceShortage, rejected.Reason)
	require.NoError(t, held.Close())
	require.Eventually(t, func() bool {
		channel, err := fresh.NewSession()
		if channel != nil {
			_ = channel.Close()
		}
		return err == nil
	}, 3*time.Second, time.Millisecond)
}

func TestRuntimeSshDispatchDoesNotResetConnectionOrStartupBudget(t *testing.T) {
	for _, startup := range []bool{false, true} {
		t.Run(map[bool]string{false: "connections", true: "startups"}[startup], func(t *testing.T) {
			svc := runtimeResourcesFixture(t, func(conf *configuration.Configuration) {
				if startup {
					conf.Ssh.MaxStartupsStart, conf.Ssh.MaxStartupsFull, conf.Ssh.MaxStartupsRate = 1, 1, 100
				} else {
					conf.Ssh.MaxConnections = 1
				}
			})
			address := runtimeSshListener(t, svc)
			if startup {
				wire, err := net.DialTimeout("tcp", address, 3*time.Second)
				require.NoError(t, err)
				defer func() { _ = wire.Close() }()
				require.NoError(t, wire.SetDeadline(time.Now().Add(5*time.Second)))
				banner, err := bufio.NewReader(wire).ReadString('\n')
				require.NoError(t, err)
				require.True(t, strings.HasPrefix(banner, "SSH-2.0-"))
			} else {
				runtimeSshDial(t, svc, address, "correct")
			}
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
			runtimeSshActivate(t, svc, next)
			excess, err := gossh.Dial("tcp", address, runtimeSshConfig(svc, "correct"))
			if excess != nil {
				_ = excess.Close()
			}
			require.Error(t, err, "reload must not create another admission budget")
		})
	}
}

func TestRuntimeSshDispatchPublicKeyProofUsesAdmittedAuthorizer(t *testing.T) {
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.HouseKeeping.InitialDelay = common.DurationOf(time.Hour)
	})
	old := server.mustDial(t)
	next := runtimeSshCandidate(t, server.service, func(conf *configuration.Configuration) {
		entry := &conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0]
		entry.AuthorizedKeys = ""
		entry.Password = crypto.Password("plain:changed")
		conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(23)
	})
	runtimeSshActivate(t, server.service, next)
	denied, err := server.dial()
	if denied != nil {
		_ = denied.Close()
	}
	require.Error(t, err, "a new connection must not use the initial public-key authorizer")
	config := runtimeSshConfig(server.service, "changed")
	config.User = server.username
	fresh, err := gossh.Dial("tcp", server.address, config)
	require.NoError(t, err)
	defer func() { _ = fresh.Close() }()
	runtimeSshRun(t, old, 0)
	runtimeSshRun(t, fresh, 23)
}

func TestRuntimeSshDispatchSurvivesRetirementOfInitialProvidersAndDrainsLaterHandlers(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	address := runtimeSshListener(t, svc)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
	runtimeSshActivate(t, svc, next)
	runtimeResourcesWaitClosed(t, svc)
	client := runtimeSshDial(t, svc, address, "correct")
	runtimeSshRun(t, client, 0)
	require.Same(t, next, runtimeSshConnection(t, svc, client).service)
	svc.handlerLifecycle().stop()
	require.False(t, svc.handlerLifecycle().wait(0), "shutdown must include a later generation's SSH handlers")
	require.NoError(t, client.Close())
	require.True(t, svc.handlerLifecycle().wait(3*time.Second))
}

type runtimeSshGatedRepository struct {
	environment.CloseableRepository
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
}

func (this *runtimeSshGatedRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	return &runtimeSshGatedEnvironment{Environment: env, repository: this}, nil
}

func (this *runtimeSshGatedRepository) Close() error {
	defer close(this.closed)
	return this.CloseableRepository.Close()
}

type runtimeSshGatedEnvironment struct {
	environment.Environment
	repository *runtimeSshGatedRepository
}

func (this *runtimeSshGatedEnvironment) Run(task environment.Task) (int, error) {
	close(this.repository.entered)
	<-this.repository.release // Deliberately finish later than transport cancellation.
	return this.Environment.Run(task)
}

func TestRuntimeSshShutdownWaitsForLaterGenerationHandlerAfterSocketClose(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	address := runtimeSshListener(t, svc)
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
	gate := &runtimeSshGatedRepository{
		CloseableRepository: next.environments,
		entered:             make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
	}
	next.environments = gate
	runtimeSshActivate(t, svc, next)
	runtimeResourcesWaitClosed(t, svc)
	client := runtimeSshDial(t, svc, address, "correct")
	channel, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = channel.Close() }()
	runDone := make(chan error, 1)
	go func() { runDone <- channel.Run("test") }()
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH execution did not start")
	}
	done := make(chan error, 1)
	go func() { done <- svc.Close() }()
	socketDone := make(chan error, 1)
	go func() { socketDone <- client.Wait() }()
	select {
	case _ = <-socketDone: // Shutdown intentionally closes the socket.
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not close the SSH socket")
	}
	select {
	case err := <-done:
		t.Fatalf("service cleanup finished before the later generation's handler returned: %v", err)
	case <-gate.closed:
		t.Fatal("provider closed while its handler was still running")
	default:
	}
	unblock()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("service cleanup did not finish after releasing the handler")
	}
	_ = <-runDone // The canceled transport need not report a successful command.
	require.True(t, svc.handlerLifecycle().wait(0))
	select {
	case <-gate.closed:
	default:
		t.Fatal("provider did not close after its last handler")
	}
}

func TestRuntimeSshProvisionalCancellationAndHandlerLeaseAreDistinct(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-config", true: "after-config"}[claimed], func(t *testing.T) {
			svc := runtimeResourcesFixture(t)
			sshContext := newLimiterSSHContext("192.0.2.1")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sshContext.Context = ctx
			server, peer := net.Pipe()
			defer func() { _ = peer.Close() }()
			wrapped, err := svc.server.ConnCallback(sshContext, server)
			require.NoError(t, err)
			require.NotNil(t, wrapped)
			if claimed {
				require.NoError(t, svc.server.ServerConfigCallback(sshContext, wrapped, &gossh.ServerConfig{}))
			}
			require.NoError(t, wrapped.Close())
			cancel()
			next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
			runtimeSshActivate(t, svc, next)
			if claimed {
				runtimeGenerationTestNotDrained(t, svc.generation)
				require.NoError(t, svc.server.DisconnectCallback(sshContext, wrapped))
			}
			runtimeResourcesWaitClosed(t, svc)
			require.ErrorIs(t, svc.server.ServerConfigCallback(sshContext, wrapped, &gossh.ServerConfig{}), context.Canceled)
			require.NoError(t, svc.server.ConnectionFailedCallback(sshContext, wrapped, context.Canceled))
			require.Empty(t, svc.runtime.allConnections())
			require.Zero(t, svc.connectionCounter().Load())
		})
	}
}

func TestRuntimeSshTunnelDispatchKeepsOldChannelsAcrossHttpTransports(t *testing.T) {
	for _, mode := range []string{"https2", "wss"} {
		t.Run(mode, func(t *testing.T) {
			f := newSshTunnelFixture(t, false, false, true, false, func(conf *configuration.Configuration) {
				conf.Flows[0].Authorization.V = &configuration.AuthorizationSimple{
					Entries: configuration.AuthorizationSimpleEntries{{Name: "test", Password: crypto.Password("plain:correct")}},
				}
				conf.HouseKeeping.InitialDelay = common.DurationOf(time.Hour)
			})
			dial := func(password string) (*gossh.Client, error) {
				conn := f.transportConn(t, mode)
				config := f.clientConfig()
				config.Auth = []gossh.AuthMethod{gossh.Password(password)}
				cc, channels, requests, err := gossh.NewClientConn(conn, "app.example.org", config)
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				client := gossh.NewClient(cc, channels, requests)
				t.Cleanup(func() { _ = client.Close() })
				return client, nil
			}
			old, err := dial("correct")
			require.NoError(t, err)
			next := runtimeSshCandidate(t, f.svc, func(conf *configuration.Configuration) {
				conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple).Entries[0].Password = crypto.Password("plain:changed")
				conf.Flows[0].Environment.V.(*configuration.EnvironmentDummy).ExitCode = template.Int64Of(19)
			})
			runtimeSshActivate(t, f.svc, next)
			_, err = dial("correct")
			require.Error(t, err)
			fresh, err := dial("changed")
			require.NoError(t, err)
			runtimeSshRun(t, old, 0)
			runtimeSshRun(t, fresh, 19)
		})
	}
}

func TestRuntimeSshSelectionAllowsOneAdmissionAfterActivationButNotAfterRelease(t *testing.T) {
	svc := runtimeResourcesFixture(t)
	selection, release, err := svc.runtime.selectCurrent()
	require.NoError(t, err)
	defer release()
	next := runtimeSshCandidate(t, svc, func(conf *configuration.Configuration) { conf.Flows[0].Title = "new" })
	runtimeSshActivate(t, svc, next)
	runtimeGenerationTestNotDrained(t, svc.generation)
	conn := &runtimeGenerationTestConnection{terminalConnectionTestTransport: runtimeAdmissionTestTransport(t)}
	finish, err := svc.runtime.admitSelected(selection, conn)
	require.NoError(t, err)
	_, err = svc.runtime.admitSelected(selection, conn)
	require.ErrorIs(t, err, context.Canceled)
	release()
	runtimeGenerationTestNotDrained(t, svc.generation)
	finish()
	runtimeResourcesWaitClosed(t, svc)
	_, err = svc.runtime.admitSelected(selection, conn)
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, conn.Close())
}
