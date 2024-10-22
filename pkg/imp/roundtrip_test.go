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
)

var (
	roundtripTestImpAddress = net.HostPort{
		Host: net.MustNewHost("localhost"),
		Port: ServicePort,
	}
	roundtripTestServiceAddress = net.HostPort{
		Host: net.MustNewHost("localhost"),
		Port: 45321,
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

	var dummyCmdPid atomic.Int64
	var dummyCmdConnectionId connection.Id
	if *roundtripTestWithKill {
		dummyCmdConnectionId, err = connection.NewId()
		require.NoError(t, err)
		dummyCmd := prepareRoundtripDummyCmd(t, dummyCmdConnectionId)
		wg.Add(1)
		go runCmd(ctx, t, dummyCmd, wg.Done, &dummyCmdPid)
		time.Sleep(100 * time.Millisecond)
	}

	defer wg.Wait()
	defer cancelFn()

	for i := 0; i < 10000; i++ {
		time.Sleep(1 * time.Millisecond)
		conn, err := gonet.DialTimeout("tcp", roundtripTestImpAddress.String(), time.Millisecond*10)
		if err != nil {
			continue
		}
		_ = conn.Close()
		break
	}

	wg.Add(1)
	go runRoundtripDummyService(t, ctx, wg.Done)

	master, err := NewImp(ctx, masterKey)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, master.Close())
	}()

	sess, err := master.Open(ctx, refImpl{sessionId})
	require.NoError(t, err)

	t.Run("ping", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		err = sess.Ping(ctx, connId)
		require.NoError(t, err)

		time.Sleep(time.Millisecond * 100)
	})

	if *roundtripTestWithKill {
		t.Run("kill", func(t *testing.T) {
			testlog.Hook(t)

			target, err := process.NewProcess(int32(dummyCmdPid.Load()))
			require.NoError(t, err)
			running, err := target.IsRunning()
			require.NoError(t, err)
			require.True(t, running)

			require.NoError(t, sess.Kill(ctx, dummyCmdConnectionId, 0, sys.SIGTERM))

			require.EventuallyWithT(t, func(t *assert.CollectT) {
				running, err = target.IsRunning()
				assert.NoError(t, err)
				assert.False(t, running)
			}, 1*time.Minute, 100*time.Millisecond)
		})

		time.Sleep(time.Millisecond * 100)
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
					conn, err := sess.InitiateTcpForward(ctx, connId, roundtripTestServiceAddress)
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

		time.Sleep(time.Millisecond * 100)
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

			time.Sleep(time.Millisecond * 100)
		}()

		time.Sleep(time.Millisecond * 200)

		assert.NotEmpty(t, local.Path())
		remote, err := net.ConnectToNamedPipe(ctx, local.Path())
		require.NoError(t, err)
		defer common.IgnoreCloseError(remote)

		_, err = remote.Write([]byte("foobar"))
		require.NoError(t, err)

		time.Sleep(time.Millisecond * 200)

		require.NoError(t, remote.Close())
		require.NoError(t, local.Close())
		iwg.Wait()

		time.Sleep(time.Millisecond * 100)
	})

	t.Run("named-pipe-noop", func(t *testing.T) {
		testlog.Hook(t)
		connId, err := connection.NewId()
		require.NoError(t, err)

		local, err := sess.InitiateNamedPipe(ctx, connId, "foo")
		require.NoError(t, err)
		require.NotNil(t, local)
		defer common.IgnoreCloseError(local)

		time.Sleep(time.Millisecond * 100)

		require.NoError(t, local.Close())

		time.Sleep(time.Millisecond * 100)
	})
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

func runRoundtripDummyProcess(_ *testing.T) {
	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGTERM)
	sig := <-sigs
	log.With("signal", sig).
		With("context", "imp-test").
		Info("received signal")
}

func runRoundtripDummyService(t *testing.T, ctx context.Context, onDone func()) {
	defer onDone()
	ln, err := gonet.Listen("tcp", roundtripTestServiceAddress.String())
	assert.NoError(t, err)
	if t.Failed() {
		return
	}
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

func prepareRoundtripDummyCmd(t *testing.T, connectionId connection.Id) *exec.Cmd {
	ex, err := os.Executable()
	require.NoError(t, err)

	cmd := exec.Command(ex, "-test.run=^"+t.Name()+"$",
		"--"+flagRoundtripTestDummyProcess,
	)
	cmd.Env = append(os.Environ(), connection.EnvName+"="+connectionId.String())
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
		if err != nil && !errors.Is(err, process.ErrorProcessNotRunning) {
			t.Errorf("Cannot get IMP process %d: %v", cmd.Process.Pid, err)
			return
		}
		_ = p.Terminate()
	}()

	if err := cmd.Wait(); err != nil {
		var ecErr *exec.ExitError
		if errors.As(err, &ecErr) {
			exitCode := ecErr.ExitCode()
			if exitCode == 666 || exitCode == 154 {
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
}

func (this refImpl) SessionId() session.Id {
	return this.sessionId
}

func (this refImpl) PublicKey() crypto.PublicKey {
	return nil
}

func (this refImpl) EndpointAddr() net.HostPort {
	return roundtripTestImpAddress
}
