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
	"syscall"
	"testing"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/sdk/testlog"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	flagRoundtripTestProcess         = "imp-roundtrip-test-process"
	flagRoundtripTestImpAddress      = "imp-roundtrip-test-imp-addr"
	flagRoundtripTestMasterPublicKey = "imp-roundtrip-test-master-public-key"
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

	roundtripTestEnabled          = flag.Bool("imp-roundtrip-test-enabled", true, "")
	roundtripTestImpProcess       = flag.Bool(flagRoundtripTestProcess, false, "")
	roundtripTestAttachToDebugger = flag.String("imp-roundtrip-test-attach-to-debugger", "", "")
	roundtripTestDebuggerOutput   = flag.String("imp-roundtrip-test-debugger-output", "", "")
	roundtripTestMasterPublicKey  = flag.String(flagRoundtripTestMasterPublicKey, "", "")
)

func init() {
	flag.Var(&roundtripTestImpAddress, flagRoundtripTestImpAddress, "")
	flag.Var(&roundtripTestServiceAddress, "imp-roundtrip-test-service-addr", "")
}

func TestRoundtrip(t *testing.T) {
	testlog.Hook(t)

	if *roundtripTestImpProcess {
		roundtripImp(t)
		return
	}

	if *roundtripTestEnabled {
		roundtrip(t)
		return
	}
}

func roundtrip(t *testing.T) {
	ctx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()

	masterKey := generatePrivateKey(t)

	var wg sync.WaitGroup
	impCmd := prepareRoundtripImpCmd(t, masterKey.PublicKey())
	wg.Add(1)
	go runCmd(ctx, t, impCmd, wg.Done)
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
	go roundtripDummyService(ctx, t, wg.Done)

	master, err := NewImp(ctx, nil, masterKey, &configuration.Imp{})
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, master.Close())
	}()

	sess, err := master.Open(ctx, refV)
	require.NoError(t, err)

	connId := connection.MustNewId()
	t.Run("echo", func(t *testing.T) {
		resp, err := sess.Echo(ctx, connId, "foo")
		require.NoError(t, err)

		assert.Equal(t, "thanks for: foo", resp)
	})
	t.Run("kill", func(t *testing.T) {
		err := sess.Kill(ctx, connId, 666, sys.SIGTRAP)
		require.Equal(t, err, ErrNoSuchProcess)
	})
	t.Run("port-forward-tcp", func(t *testing.T) {
		hc := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (gonet.Conn, error) {
					assert.Equal(t, network, "tcp")
					assert.Equal(t, addr, "foo:80")
					conn, err := sess.InitiateDirectTcp(ctx, connId, roundtripTestServiceAddress.Host.String(), uint32(roundtripTestServiceAddress.Port))
					assert.NoError(t, err)
					return conn, nil
				},
			},
		}
		resp, err := hc.Get("http://foo/")
		require.NoError(t, err)
		defer common.IgnoreCloseError(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)

		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "OK!", string(b))
	})

	// Has to be the last run!
	t.Run("exit", func(t *testing.T) {
		err := sess.Exit(ctx, connId, 666)
		if net.IsClosedError(err) {
			// Ok
		} else if err != nil {
			t.Fatal(err)
		}
	})
}

func roundtripImp(t *testing.T) {
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
		return
	}()

	svc := Service{
		Addr:            roundtripTestImpAddress.String(),
		MasterPublicKey: decodePublicKeyString(t, *roundtripTestMasterPublicKey),
	}

	err := svc.Serve(ctx)
	assert.NoError(t, err)
}

func roundtripDummyService(ctx context.Context, t *testing.T, onDone func()) {
	defer onDone()
	ln, err := gonet.Listen("tcp", roundtripTestServiceAddress.String())
	require.NoError(t, err)
	defer common.IgnoreCloseError(ln)

	srv := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK!"))
		}),
	}

	go func() {
		err := srv.Serve(ln)
		if !net.IsClosedError(err) && !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
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

func prepareRoundtripImpCmd(t *testing.T, masterPublicKey crypto.PublicKey) *exec.Cmd {
	ex, err := os.Executable()
	require.NoError(t, err)

	args := []string{"-test.run=^" + t.Name() + "$",
		"--" + flagRoundtripTestProcess,
		"--" + flagRoundtripTestImpAddress + "=" + roundtripTestImpAddress.String(),
		"--" + flagRoundtripTestMasterPublicKey + "=" + base64.StdEncoding.EncodeToString(masterPublicKey.Marshal()),
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

func runCmd(ctx context.Context, t *testing.T, cmd *exec.Cmd, onDone func()) {
	defer onDone()
	err := cmd.Start()
	require.NoError(t, err)

	go func() {
		<-ctx.Done()
		p, err := process.NewProcess(int32(cmd.Process.Pid))
		if err != nil && !errors.Is(err, process.ErrorProcessNotRunning) {
			t.Errorf("Cannot get IMP process %d: %v", cmd.Process.Pid, err)
			return
		}
		if err := p.Terminate(); err != nil {
			t.Logf("Cannot terminate IMP process %d: %v", cmd.Process.Pid, err)
		}
	}()

	if err := cmd.Wait(); err != nil {
		var ecErr *exec.ExitError
		if errors.As(err, &ecErr) {
			exitCode := ecErr.ExitCode()
			if exitCode == 666 {
				// Expected exit code.
				return
			}
			t.Fatalf("IMP failed with %d; see above", ecErr.ExitCode())
			return
		}
		t.Fatalf("IMP failed with unexpected execution error: %v", err)
	}
}

func decodePublicKeyString(t *testing.T, in string) crypto.PublicKey {
	b, err := base64.StdEncoding.DecodeString(in)
	require.NoError(t, err)
	result, err := crypto.ParsePublicKeyBytes(b)
	require.NoError(t, err)
	return result
}

var refV = refImpl{}

type refImpl struct {
}

func (this refImpl) PublicKey() crypto.PublicKey {
	return nil // TODO! Maybe do it better...
}

func (this refImpl) EndpointAddr() net.HostPort {
	return roundtripTestImpAddress
}
