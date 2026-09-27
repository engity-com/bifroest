package imp

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	gonet "net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	flagRoundtripTestDummyProcess    = "imp-roundtrip-test-dummy-process"
	flagRoundtripTestImpProcess      = "imp-roundtrip-test-imp-process"
	flagRoundtripTestImpAddress      = "imp-roundtrip-test-imp-addr"
	flagRoundtripTestMasterPublicKey = "imp-roundtrip-test-master-public-key"
	flagRoundtripTestSessionId       = "imp-roundtrip-test-session-id"
	roundtripTestDummyReadyEnv       = "BIFROEST_IMP_ROUNDTRIP_DUMMY_READY"
)

var (
	roundtripTestImpAddress = net.HostPort{
		Host: net.MustNewHost("localhost"),
		Port: ServicePort,
	}
	roundtripTestServiceAddress = net.HostPort{
		Host: net.MustNewHost("localhost"),
	}
	roundtripTestSessionId session.Id

	roundtripTestEnabled          = flag.Bool("imp-roundtrip-test-enabled", true, "")
	roundtripTestWithKill         = flag.Bool("imp-roundtrip-test-with-kill", true, "")
	roundtripTestDummyProcess     = flag.Bool(flagRoundtripTestDummyProcess, false, "")
	roundtripTestImpProcess       = flag.Bool(flagRoundtripTestImpProcess, false, "")
	roundtripTestAttachToDebugger = flag.String("imp-roundtrip-test-attach-to-debugger", "", "")
	roundtripTestDebuggerOutput   = flag.String("imp-roundtrip-test-debugger-output", "", "")
	roundtripTestMasterPublicKey  = flag.String(flagRoundtripTestMasterPublicKey, "", "")
)

func init() {
	flag.Var(&roundtripTestImpAddress, flagRoundtripTestImpAddress, "")
	flag.Var(&roundtripTestServiceAddress, "imp-roundtrip-test-service-addr", "")
	flag.Var(&roundtripTestSessionId, flagRoundtripTestSessionId, "")
}

func TestRoundtripAsSeparateProcess(t *testing.T) {
	testlog.Hook(t)

	if *roundtripTestImpProcess {
		runRoundtripImpProcess(t)
		return
	}

	if *roundtripTestDummyProcess {
		runRoundtripDummyProcess(t)
		return
	}

	if *roundtripTestEnabled {
		runRoundtripMaster(t, func(masterKey crypto.PublicKey, sessId session.Id) func(context.Context, func()) {
			impCmd := prepareRoundtripImpCmd(t, masterKey, sessId)
			return func(ctx context.Context, onDone func()) {
				runCmd(ctx, t, impCmd, onDone, nil)
			}
		})
		return
	}
}

func TestRoundtrip(t *testing.T) {
	testlog.Hook(t)

	if *roundtripTestDummyProcess {
		runRoundtripDummyProcess(t)
		return
	}

	if *roundtripTestEnabled {
		runRoundtripMaster(t, func(masterKey crypto.PublicKey, sessId session.Id) func(context.Context, func()) {
			svc := Service{
				Addr:            roundtripTestImpAddress.String(),
				MasterPublicKey: masterKey,
				SessionId:       sessId,
			}
			return func(ctx context.Context, onDone func()) {
				defer onDone()
				assert.NoError(t, svc.Serve(ctx))
			}
		})
		return
	}
}

func runRoundtripMaster(t *testing.T, impPreparation func(crypto.PublicKey, session.Id) func(context.Context, func())) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	masterKey := generatePrivateKey(t)
	sessionId, err := session.NewId()
	require.NoError(t, err)

	var wg sync.WaitGroup

	impCmd := impPreparation(masterKey.PublicKey(), sessionId)
	wg.Add(1)
	go impCmd(ctx, wg.Done)
	defer wg.Wait()
	defer cancelFn()

	var dummyCmdPid atomic.Int64
	var dummyCmdDone chan struct{}
	var dummyCmdExecutionId execution.Id
	if *roundtripTestWithKill {
		dummyCmdExecutionId, err = execution.NewId()
		require.NoError(t, err)
		dummyCmd := prepareRoundtripDummyCmd(t, dummyCmdExecutionId)
		readyFile := filepath.Join(t.TempDir(), "dummy-ready")
		dummyCmd.Env = append(dummyCmd.Env, roundtripTestDummyReadyEnv+"="+readyFile)
		dummyCmdDone = make(chan struct{})
		wg.Add(1)
		go func() {
			defer close(dummyCmdDone)
			runCmd(ctx, t, dummyCmd, wg.Done, &dummyCmdPid)
		}()
		require.Eventually(t, func() bool {
			if dummyCmdPid.Load() <= 0 {
				return false
			}
			_, err := os.Stat(readyFile)
			return err == nil
		}, 10*time.Second, 10*time.Millisecond, "dummy process did not become ready")
	}

	for i := 0; i < 10000; i++ {
		common.SleepSilently(ctx, 1*time.Millisecond)
		conn, err := gonet.DialTimeout("tcp", roundtripTestImpAddress.String(), time.Millisecond*10)
		if err != nil {
			continue
		}
		_ = conn.Close()
		break
	}

	listener, err := gonet.Listen("tcp", roundtripTestServiceAddress.String())
	require.NoError(t, err)
	serviceAddress := roundtripTestServiceAddress
	serviceAddress.Port = uint16(listener.Addr().(*gonet.TCPAddr).Port)
	wg.Add(1)
	go runRoundtripDummyService(t, ctx, wg.Done, listener)

	master, err := NewImp(ctx, masterKey)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, master.Close())
	}()

	sess, err := master.Open(ctx, refImpl{sessionId: sessionId})
	require.NoError(t, err)

	t.Run("ping", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		err = sess.Ping(ctx, connId)
		require.NoError(t, err)

		common.SleepSilently(ctx, time.Millisecond*100)
	})

	if *roundtripTestWithKill {
		t.Run("kill", func(t *testing.T) {
			testlog.Hook(t)
			executionSession, ok := sess.(ExecutionSession)
			require.True(t, ok)
			connId, err := connection.NewId()
			require.NoError(t, err)

			require.NoError(t, executionSession.KillExecution(ctx, connId, dummyCmdExecutionId, 0, sys.SIGTERM))
			select {
			case <-dummyCmdDone:
			case <-time.After(time.Minute):
				t.Fatal("dummy process did not exit after SIGTERM")
			}
		})
	}

	t.Run("tcp-forward", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		hc := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (gonet.Conn, error) {
					assert.Equal(t, network, "tcp")
					assert.Equal(t, addr, "foo:80")
					conn, err := sess.InitiateTcpForward(ctx, connId, serviceAddress)
					assert.NoError(t, err)
					return conn, nil
				},
			},
		}
		// Because it will keep the connection to the imp open. If we do not close it, it will block forever...
		defer hc.CloseIdleConnections()

		resp, err := hc.Get("http://foo/")
		require.NoError(t, err)
		defer common.IgnoreCloseError(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)

		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "OK!", string(b))

		common.SleepSilently(ctx, time.Millisecond*100)
	})

	t.Run("named-pipe", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		local, err := sess.InitiateNamedPipe(ctx, connId, "foo")
		require.NoError(t, err)
		require.NotNil(t, local)
		defer common.IgnoreCloseError(local)

		var iwg sync.WaitGroup
		iwg.Add(1)
		go func() {
			defer iwg.Done()
			localConn, err := local.AcceptConn()
			require.NoError(t, err)
			if t.Failed() {
				return
			}
			defer func() {
				_ = localConn.Close()
			}()

			buf := make([]byte, 6)
			_, err = localConn.Read(buf)
			assert.NoError(t, err)

			assert.Equal(t, "foobar", string(buf))

			common.SleepSilently(ctx, time.Millisecond*100)
		}()

		common.SleepSilently(ctx, time.Millisecond*200)

		assert.NotEmpty(t, local.Path())
		remote, err := net.ConnectToNamedPipe(ctx, local.Path())
		require.NoError(t, err)
		defer common.IgnoreCloseError(remote)

		_, err = remote.Write([]byte("foobar"))
		require.NoError(t, err)

		common.SleepSilently(ctx, time.Millisecond*200)

		require.NoError(t, remote.Close())
		require.NoError(t, local.Close())
		iwg.Wait()

		common.SleepSilently(ctx, time.Millisecond*100)
	})

	t.Run("named-pipe-noop", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		local, err := sess.InitiateNamedPipe(ctx, connId, "foo")
		require.NoError(t, err)
		require.NotNil(t, local)
		defer common.IgnoreCloseError(local)

		common.SleepSilently(ctx, time.Millisecond*100)

		require.NoError(t, local.Close())

		common.SleepSilently(ctx, time.Millisecond*100)
	})

	t.Run("reverse-tcp", func(t *testing.T) {
		connId, err := connection.NewId()
		require.NoError(t, err)
		ln, err := sess.ListenReverseTCP(ctx, connId, "127.0.0.1", 0)
		require.NoError(t, err)
		defer common.IgnoreCloseError(ln)
		addr, ok := ln.Addr().(*gonet.TCPAddr)
		require.True(t, ok)
		require.Equal(t, "127.0.0.1", addr.IP.String())
		require.NotZero(t, addr.Port)

		for i := 0; i < 3; i++ {
			client, err := gonet.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
			require.NoError(t, err)
			func() {
				defer common.IgnoreCloseError(client)
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				message := strings.Repeat("hello\x00world", 100)
				_, err := client.Write([]byte(message))
				require.NoError(t, err)
				require.NoError(t, client.(*gonet.TCPConn).CloseWrite())

				accepted, err := ln.Accept()
				require.NoError(t, err)
				defer common.IgnoreCloseError(accepted)
				require.NoError(t, accepted.SetDeadline(time.Now().Add(5*time.Second)))
				assert.Equal(t, client.LocalAddr().String(), accepted.RemoteAddr().String())
				assert.Equal(t, client.RemoteAddr().String(), accepted.LocalAddr().String())
				assert.Equal(t, "tcp", accepted.RemoteAddr().Network())
				_, ok := accepted.RemoteAddr().(*gonet.TCPAddr)
				assert.True(t, ok)
				got, err := io.ReadAll(accepted)
				require.NoError(t, err)
				assert.Equal(t, message, string(got))
				_, err = accepted.Write(got)
				require.NoError(t, err)
				reply := make([]byte, len(message))
				_, err = io.ReadFull(client, reply)
				require.NoError(t, err)
				assert.Equal(t, message, string(reply))
				require.NoError(t, accepted.(interface{ CloseWrite() error }).CloseWrite())
				require.NoError(t, accepted.(interface{ CloseWrite() error }).CloseWrite())
				_, err = accepted.Write([]byte("after EOF"))
				require.ErrorIs(t, err, io.ErrClosedPipe)
				remaining, err := io.ReadAll(client)
				require.NoError(t, err)
				assert.Empty(t, remaining)
			}()
		}
		// The reply and its EOF arrive before the client starts reading. Both
		// directions have already sent EOF, but the reply must remain available.
		for i := 0; i < 20; i++ {
			client, err := gonet.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
			require.NoError(t, err)
			func() {
				defer common.IgnoreCloseError(client)
				require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))
				accepted, err := ln.Accept()
				require.NoError(t, err)
				defer common.IgnoreCloseError(accepted)
				require.NoError(t, accepted.SetDeadline(time.Now().Add(10*time.Second)))
				request := strings.Repeat("request\x00", 4096)
				response := strings.Repeat("response\x00", 4096)
				_, err = client.Write([]byte(request))
				require.NoError(t, err)
				require.NoError(t, client.(*gonet.TCPConn).CloseWrite())
				got, err := io.ReadAll(accepted)
				require.NoError(t, err)
				require.Equal(t, request, string(got))
				_, err = accepted.Write([]byte(response))
				require.NoError(t, err)
				require.NoError(t, accepted.(interface{ CloseWrite() error }).CloseWrite())
				require.NoError(t, accepted.(interface{ CloseWrite() error }).CloseWrite())
				_, err = accepted.Write([]byte("after EOF"))
				require.ErrorIs(t, err, io.ErrClosedPipe)
				time.Sleep(10 * time.Millisecond)
				got, err = io.ReadAll(client)
				require.NoError(t, err)
				require.Equal(t, response, string(got))
			}()
		}
		first, err := gonet.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
		require.NoError(t, err)
		defer common.IgnoreCloseError(first)
		second, err := gonet.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
		require.NoError(t, err)
		defer common.IgnoreCloseError(second)
		firstAccepted, err := ln.Accept()
		require.NoError(t, err)
		defer common.IgnoreCloseError(firstAccepted)
		secondAccepted, err := ln.Accept()
		require.NoError(t, err)
		defer common.IgnoreCloseError(secondAccepted)
		origins := map[string]string{
			first.LocalAddr().String():  first.RemoteAddr().String(),
			second.LocalAddr().String(): second.RemoteAddr().String(),
		}
		for _, accepted := range []gonet.Conn{firstAccepted, secondAccepted} {
			local, ok := origins[accepted.RemoteAddr().String()]
			require.True(t, ok, "unknown origin: %s", accepted.RemoteAddr())
			assert.Equal(t, local, accepted.LocalAddr().String())
			delete(origins, accepted.RemoteAddr().String())
		}
		require.Empty(t, origins)

		_, err = sess.ListenReverseTCP(ctx, connId, "127.0.0.1", uint16(addr.Port))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "address already in use")
		_, err = sess.ListenReverseTCP(ctx, connId, "bad:host", 0)
		require.Error(t, err)

		wildcard, err := sess.ListenReverseTCP(ctx, connId, "", 0)
		require.NoError(t, err)
		assert.True(t, wildcard.Addr().(*gonet.TCPAddr).IP.IsUnspecified())
		require.NoError(t, wildcard.Close())

		blocked := make(chan error, 1)
		go func() { _, e := ln.Accept(); blocked <- e }()
		require.NoError(t, ln.Close())
		require.NoError(t, ln.Close())
		select {
		case err := <-blocked:
			require.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("listener Close did not release Accept")
		}

		require.Eventually(t, func() bool {
			rebound, e := sess.ListenReverseTCP(ctx, connId, "127.0.0.1", uint16(addr.Port))
			if e != nil {
				return false
			}
			_ = rebound.Close()
			return true
		}, 5*time.Second, 20*time.Millisecond)

		listenCtx, cancel := context.WithCancel(ctx)
		cancelled, err := sess.ListenReverseTCP(listenCtx, connId, "127.0.0.1", 0)
		require.NoError(t, err)
		defer common.IgnoreCloseError(cancelled)
		go func() { _, e := cancelled.Accept(); blocked <- e }()
		cancel()
		select {
		case err := <-blocked:
			require.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("context cancellation did not release Accept")
		}
		require.Eventually(t, func() bool {
			rebound, e := sess.ListenReverseTCP(ctx, connId, "127.0.0.1", uint16(cancelled.Addr().(*gonet.TCPAddr).Port))
			if e != nil {
				return false
			}
			_ = rebound.Close()
			return true
		}, 5*time.Second, 20*time.Millisecond)
	})

	t.Run("get-environment", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		env, err := sess.GetEnvironment(ctx, connId)
		require.NoError(t, err)

		var expected sys.EnvVars
		expected.Add(os.Environ()...)
		require.Equal(t, expected, env)
	})

	t.Run("reverse-tcp-transport-close", func(t *testing.T) {
		connId, err := connection.NewId()
		require.NoError(t, err)
		dialed := make(chan gonet.Conn, 1)
		transportSession, err := master.Open(ctx, refImpl{sessionId: sessionId, dialed: dialed})
		require.NoError(t, err)
		defer common.IgnoreCloseError(transportSession)
		ln, err := transportSession.ListenReverseTCP(ctx, connId, "127.0.0.1", 0)
		require.NoError(t, err)
		defer common.IgnoreCloseError(ln)
		port := uint16(ln.Addr().(*gonet.TCPAddr).Port)
		blocked := make(chan error, 1)
		go func() { _, e := ln.Accept(); blocked <- e }()
		require.NoError(t, (<-dialed).Close())
		select {
		case err := <-blocked:
			require.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("transport failure did not release Accept")
		}
		require.Eventually(t, func() bool {
			rebound, e := sess.ListenReverseTCP(ctx, connId, "127.0.0.1", port)
			if e != nil {
				return false
			}
			_ = rebound.Close()
			return true
		}, 5*time.Second, 20*time.Millisecond)
	})

	t.Run("reverse-tcp-session-close", func(t *testing.T) {
		connId, err := connection.NewId()
		require.NoError(t, err)
		child, err := master.Open(ctx, refImpl{sessionId: sessionId})
		require.NoError(t, err)
		ln, err := child.ListenReverseTCP(ctx, connId, "127.0.0.1", 0)
		require.NoError(t, err)
		defer common.IgnoreCloseError(ln)
		port := uint16(ln.Addr().(*gonet.TCPAddr).Port)
		blocked := make(chan error, 1)
		go func() { _, e := ln.Accept(); blocked <- e }()
		require.NoError(t, child.Close())
		select {
		case err := <-blocked:
			require.Error(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("session Close did not release Accept")
		}
		require.Eventually(t, func() bool {
			rebound, e := sess.ListenReverseTCP(ctx, connId, "127.0.0.1", port)
			if e != nil {
				return false
			}
			_ = rebound.Close()
			return true
		}, 5*time.Second, 20*time.Millisecond)
	})

	common.SleepSilently(ctx, time.Millisecond*100)

}

func runRoundtripImpProcess(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.With("signal", sig).
			With("context", "imp-test").
			Info("received signal")
		cancelFn()
	}()

	svc := Service{
		Addr:            roundtripTestImpAddress.String(),
		MasterPublicKey: decodePublicKeyString(t, *roundtripTestMasterPublicKey),
		SessionId:       roundtripTestSessionId,
	}

	err := svc.Serve(ctx)
	assert.NoError(t, err)
}

func runRoundtripDummyProcess(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGTERM)
	require.NoError(t, os.WriteFile(os.Getenv(roundtripTestDummyReadyEnv), nil, 0600))
	sig := <-sigs
	log.With("signal", sig).
		With("context", "imp-test").
		Info("received signal")
}

func runRoundtripDummyService(t *testing.T, ctx context.Context, onDone func(), ln gonet.Listener) {
	defer onDone()
	defer common.IgnoreCloseError(ln)

	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK!"))
		}),
	}

	go func() {
		err := srv.Serve(ln)
		if !sys.IsClosedError(err) && !errors.Is(err, http.ErrServerClosed) {
			assert.NoError(t, err)
		}
	}()

	<-ctx.Done()
}

func generatePrivateKey(t *testing.T) crypto.PrivateKey {
	req := crypto.KeyRequirement{
		Type: crypto.KeyTypeEd25519,
	}
	result, err := req.GenerateKey(nil)
	require.NoError(t, err)
	return result
}

func prepareRoundtripImpCmd(t *testing.T, masterPublicKey crypto.PublicKey, sessionId session.Id) *exec.Cmd {
	ex, err := os.Executable()
	require.NoError(t, err)

	args := []string{"-test.run=^" + t.Name() + "$",
		"--" + flagRoundtripTestImpProcess,
		"--" + flagRoundtripTestImpAddress + "=" + roundtripTestImpAddress.String(),
		"--" + flagRoundtripTestMasterPublicKey + "=" + base64.StdEncoding.EncodeToString(masterPublicKey.Marshal()),
		"--" + flagRoundtripTestSessionId + "=" + sessionId.String(),
	}
	var cmd *exec.Cmd
	if addr := *roundtripTestAttachToDebugger; addr != "" {
		pArgs := []string{"--listen=" + addr, "--headless=true", "--api-version=2", "--accept-multiclient"}
		if fn := *roundtripTestDebuggerOutput; fn != "" {
			_ = os.MkdirAll(filepath.Dir(fn), 0755)
			pArgs = append(pArgs, "--log-dest="+fn)
		}
		pArgs = append(pArgs, "exec", ex, "--")
		ex = "dlv"
		args = append(pArgs, args...)
	}
	cmd = exec.Command(ex, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func prepareRoundtripDummyCmd(t *testing.T, executionId execution.Id) *exec.Cmd {
	ex, err := os.Executable()
	require.NoError(t, err)

	cmd := exec.Command(ex, "-test.run=^"+t.Name()+"$",
		"--"+flagRoundtripTestDummyProcess,
	)
	cmd.Env = append(os.Environ(), execution.EnvName+"="+executionId.String())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func runCmd(ctx context.Context, t *testing.T, cmd *exec.Cmd, onDone func(), pidDrain *atomic.Int64) {
	defer onDone()
	err := cmd.Start()
	assert.NoError(t, err)
	if t.Failed() {
		return
	}

	if pidDrain != nil {
		pidDrain.Store(int64(cmd.Process.Pid))
	}

	go func() {
		<-ctx.Done()
		p, err := process.NewProcess(int32(cmd.Process.Pid))
		if err != nil || p == nil || p.Terminate() != nil {
			_ = cmd.Process.Kill()
		}
	}()

	if err := cmd.Wait(); err != nil {
		var ecErr *exec.ExitError
		if errors.As(err, &ecErr) {
			exitCode := ecErr.ExitCode()
			if exitCode == 666 || exitCode == 154 || exitCode == 128+int(sys.SIGTERM) {
				// Expected exit code.
				return
			}
			t.Errorf("IMP failed with %d; see above", ecErr.ExitCode())
			return
		}
		t.Errorf("IMP failed with unexpected execution error: %v", err)
	}
}

func decodePublicKeyString(t *testing.T, in string) crypto.PublicKey {
	b, err := base64.StdEncoding.DecodeString(in)
	require.NoError(t, err)
	result, err := crypto.ParsePublicKeyBytes(b)
	require.NoError(t, err)
	return result
}

type refImpl struct {
	sessionId session.Id
	dialed    chan gonet.Conn
}

func (this refImpl) SessionId() session.Id {
	return this.sessionId
}

func (this refImpl) PublicKey() crypto.PublicKey {
	return nil
}

func (this refImpl) Dial(ctx context.Context) (gonet.Conn, error) {
	conn, err := new(gonet.Dialer).DialContext(ctx, "tcp", roundtripTestImpAddress.String())
	if err == nil && this.dialed != nil {
		this.dialed <- conn
	}
	return conn, err
}
