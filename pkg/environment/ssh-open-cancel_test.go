package environment

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSshEnvironmentCancellationBeforeChannelOpenReply(t *testing.T) {
	for _, test := range []struct {
		name        string
		taskType    TaskType
		channelType string
		wantCode    int
	}{
		{"shell", TaskTypeShell, "session", 7},
		{"sftp", TaskTypeSftp, "session", 0},
		{"direct-tcpip", TaskTypeShell, "direct-tcpip", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			pendingOpen := make(chan string, 1)
			target := newSshTargetWithPendingOpenAndCallback(t, pendingOpen, nil)
			t.Cleanup(target.Close)

			lifetime, cancelLifetime := newSshTestContext()
			t.Cleanup(cancelLifetime)
			conn := &sshTestConnection{id: connection.MustNewId(), context: lifetime}
			auth := &sshTestAuthorization{session: &sshTestStoredSession{id: session.MustNewId()}}
			conf := &configuration.EnvironmentSsh{}
			require.NoError(t, conf.SetDefaults())
			conf.Address = template.MustNewString(target.Address())
			conf.User = template.MustNewString("target-user")
			conf.AcceptAllHostKeys = true
			repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = repository.Close() })

			ctx, cancel := newSshTestContext()
			t.Cleanup(cancel)
			newTask := func(ctx *sshTestContext) *sshTestTask {
				return &sshTestTask{
					context: ctx, connection: conn, authorization: auth,
					session: newSshTestSession(ctx, "show-environment", nil), taskType: test.taskType,
				}
			}
			task := newTask(ctx)
			resolved, err := repository.Ensure(task)
			require.NoError(t, err)
			environment := resolved.(*sshEnvironment)
			transport, err := repository.transportFor(environment)
			require.NoError(t, err)

			type result struct {
				code int
				conn io.ReadWriteCloser
				err  error
			}
			open := func(ctx *sshTestContext) result {
				if test.channelType == "direct-tcpip" {
					conn, err := environment.NewDestinationConnection(ctx, bnet.MustNewHostPort("example.org:443"))
					return result{conn: conn, err: err}
				}
				code, err := environment.Run(newTask(ctx))
				return result{code: code, err: err}
			}
			finished := make(chan result, 1)
			go func() { finished <- open(ctx) }()
			select {
			case channelType := <-pendingOpen:
				require.Equal(t, test.channelType, channelType)
			case <-time.After(2 * time.Second):
				t.Fatal("target did not receive a channel-open request")
			}
			require.Equal(t, 1, len(transport.channels))
			cancel()
			select {
			case actual := <-finished:
				require.ErrorIs(t, actual.err, context.Canceled)
				require.Nil(t, actual.conn)
				if test.channelType != "direct-tcpip" {
					require.Equal(t, -1, actual.code)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("canceled channel open did not return")
			}
			require.Eventually(t, func() bool {
				repository.mutex.Lock()
				defer repository.mutex.Unlock()
				select {
				case <-transport.done:
					return len(transport.channels) == 0 && repository.transports[conn.id] == nil
				default:
					return false
				}
			}, 2*time.Second, 10*time.Millisecond, "canceled open retained a slot or shared transport")

			freshCtx, cancelFresh := newSshTestContext()
			t.Cleanup(cancelFresh)
			timer := time.AfterFunc(3*time.Second, cancelFresh)
			t.Cleanup(func() { timer.Stop() })
			freshFinished := make(chan result, 1)
			go func() { freshFinished <- open(freshCtx) }()
			select {
			case actual := <-freshFinished:
				require.NoError(t, actual.err)
				if actual.conn != nil {
					require.NoError(t, actual.conn.Close())
				} else {
					require.Equal(t, test.wantCode, actual.code)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("fresh task did not finish after canceled channel open")
			}
			require.Equal(t, int32(2), target.connections.Load())
			freshTransport, err := repository.transportFor(environment)
			require.NoError(t, err)
			require.NotSame(t, transport, freshTransport)
		})
	}
}

func TestSshEnvironmentPendingOpenCancellationClosesActiveChannel(t *testing.T) {
	pendingOpen := make(chan string, 1)
	target := newSshTargetWithPendingOpenAndCallback(t, pendingOpen, nil)
	target.pendingOpenAfter = 1
	t.Cleanup(target.Close)

	lifetime, cancelLifetime := newSshTestContext()
	t.Cleanup(cancelLifetime)
	conn := &sshTestConnection{id: connection.MustNewId(), context: lifetime}
	auth := &sshTestAuthorization{session: &sshTestStoredSession{id: session.MustNewId()}}
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repository.Close() })

	activeCtx, cancelActive := newSshTestContext()
	t.Cleanup(cancelActive)
	activeDeadline := time.AfterFunc(10*time.Second, cancelActive)
	t.Cleanup(func() { activeDeadline.Stop() })
	task := &sshTestTask{
		context: activeCtx, connection: conn, authorization: auth,
		session: newSshTestSession(activeCtx, "", nil), taskType: TaskTypeShell,
	}
	resolved, err := repository.Ensure(task)
	require.NoError(t, err)
	environment := resolved.(*sshEnvironment)
	active, err := environment.NewDestinationConnection(activeCtx, bnet.MustNewHostPort("example.org:443"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = active.Close() })
	transport, err := repository.transportFor(environment)
	require.NoError(t, err)
	require.Equal(t, 1, len(transport.channels))
	assertEcho := func(stream io.ReadWriteCloser, payload string) {
		t.Helper()
		type result struct {
			echo string
			err  error
		}
		finished := make(chan result, 1)
		go func() {
			if _, err := stream.Write([]byte(payload)); err != nil {
				finished <- result{err: err}
				return
			}
			buffer := make([]byte, len(payload))
			_, err := io.ReadFull(stream, buffer)
			finished <- result{echo: string(buffer), err: err}
		}()
		select {
		case actual := <-finished:
			require.NoError(t, actual.err)
			require.Equal(t, payload, actual.echo)
		case <-time.After(2 * time.Second):
			t.Fatal("target did not echo channel data")
		}
	}
	assertEcho(active, "active")

	pendingCtx, cancelPending := newSshTestContext()
	t.Cleanup(cancelPending)
	pendingResult := make(chan error, 1)
	go func() {
		opened, err := environment.NewDestinationConnection(pendingCtx, bnet.MustNewHostPort("example.org:443"))
		if opened != nil {
			_ = opened.Close()
		}
		pendingResult <- err
	}()
	select {
	case channelType := <-pendingOpen:
		require.Equal(t, "direct-tcpip", channelType)
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive the second channel-open request")
	}
	require.Equal(t, 2, len(transport.channels))
	readResult := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(active, make([]byte, 1))
		readResult <- err
	}()
	cancelPending()
	select {
	case err := <-pendingResult:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("canceled second channel open did not return")
	}
	select {
	case err := <-readResult:
		require.Error(t, err, "active channel remained readable after transport closure")
	case <-time.After(2 * time.Second):
		t.Fatal("active channel was not interrupted by transport closure")
	}
	require.Eventually(t, func() bool {
		repository.mutex.Lock()
		defer repository.mutex.Unlock()
		select {
		case <-transport.done:
			return repository.transports[conn.id] == nil && len(transport.channels) == 1
		default:
			return false
		}
	}, 2*time.Second, 10*time.Millisecond, "canceled open did not release its slot and remove the shared transport")
	_ = active.Close()
	require.Eventually(t, func() bool { return len(transport.channels) == 0 }, 2*time.Second, 10*time.Millisecond)

	freshCtx, cancelFresh := newSshTestContext()
	t.Cleanup(cancelFresh)
	freshDeadline := time.AfterFunc(3*time.Second, cancelFresh)
	t.Cleanup(func() { freshDeadline.Stop() })
	type openResult struct {
		conn io.ReadWriteCloser
		err  error
	}
	freshResult := make(chan openResult)
	go func() {
		opened, err := environment.NewDestinationConnection(freshCtx, bnet.MustNewHostPort("example.org:443"))
		select {
		case freshResult <- openResult{opened, err}:
		case <-freshCtx.Done():
			if opened != nil {
				_ = opened.Close()
			}
		}
	}()
	select {
	case result := <-freshResult:
		require.NoError(t, result.err)
		require.NotNil(t, result.conn)
		t.Cleanup(func() { _ = result.conn.Close() })
		assertEcho(result.conn, "fresh")
	case <-time.After(2 * time.Second):
		t.Fatal("fresh connection did not open after canceled second channel")
	}
	freshTransport, err := repository.transportFor(environment)
	require.NoError(t, err)
	require.NotSame(t, transport, freshTransport)
	require.Equal(t, int32(2), target.connections.Load())
}

func TestSshTransportCloseProgressWhileAgentMuHeld(t *testing.T) {
	pendingOpen := make(chan string, 1)
	target := newSshTargetWithPendingOpenAndCallback(t, pendingOpen, nil)
	t.Cleanup(target.Close)

	lifetime, cancelLifetime := newSshTestContext()
	t.Cleanup(cancelLifetime)
	conn := &sshTestConnection{id: connection.MustNewId(), context: lifetime}
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repository, err := NewSshRepositoryWithHostKeys(context.Background(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repository.Close() })

	task := &sshTestTask{
		context: lifetime, connection: conn,
		authorization: &sshTestAuthorization{session: &sshTestStoredSession{id: session.MustNewId()}},
		session:       newSshTestSession(lifetime, "", nil), taskType: TaskTypeShell,
	}
	resolved, err := repository.Ensure(task)
	require.NoError(t, err)
	environment := resolved.(*sshEnvironment)
	transport, err := repository.transportFor(environment)
	require.NoError(t, err)

	transport.agentMu.Lock()
	locked := true
	unlock := func() {
		if locked {
			transport.agentMu.Unlock()
			locked = false
		}
	}
	t.Cleanup(unlock)

	openResult := make(chan error, 1)
	go func() {
		channel, _, err := transport.client.OpenChannel("session", nil)
		if channel != nil {
			_ = channel.Close()
		}
		openResult <- err
	}()
	select {
	case channelType := <-pendingOpen:
		require.Equal(t, "session", channelType)
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive the pending channel open")
	}

	removed := make(chan struct{})
	go func() {
		repository.removeTransport(conn.id, transport)
		close(removed)
	}()
	select {
	case <-transport.done:
	case <-time.After(2 * time.Second):
		t.Fatal("transport did not close while agentMu was held")
	}
	select {
	case err := <-openResult:
		require.Error(t, err, "pending channel open unexpectedly succeeded")
	case <-time.After(2 * time.Second):
		t.Fatal("pending channel open remained blocked while agentMu was held")
	}
	select {
	case <-removed:
		t.Fatal("removeTransport finished before agentMu was released")
	default:
	}

	unlock()
	select {
	case <-removed:
	case <-time.After(2 * time.Second):
		t.Fatal("removeTransport did not finish after agentMu was released")
	}
	fresh, err := repository.transportFor(environment)
	require.NoError(t, err)
	require.NotSame(t, transport, fresh)
	require.Equal(t, int32(2), target.connections.Load())
}
