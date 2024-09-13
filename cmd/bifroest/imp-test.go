package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	impTestDebuggerPort string
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("imp-test", "Testing the imp service.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doImpTest()
		})
	cmd.Flag("attachDebuggerTo", "Address to attach the Delve debugger to.").
		PlaceHolder("[<host>]:<port>").
		StringVar(&impTestDebuggerPort)
})

func doImpTest() error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			sig := <-sigs
			log.With("signal", sig).
				With("context", "imp-test").
				Info("received signal")
			cancelFunc()
			return
		}
	}()

	token := make([]byte, 12)
	if _, err := rand.Read(token); err != nil {
		return failf("cannot generate token: %w", err)
	}
	tokenHex := hex.EncodeToString(token)

	sess := &mockSession{uuid.New()}

	ex, err := os.Executable()
	if err != nil {
		return failf("cannot resolve own executable: %w", err)
	}
	var cmd *exec.Cmd
	if impTestDebuggerPort != "" {
		cmd = exec.Command("dlv",
			"--listen="+impTestDebuggerPort, "--headless=true", "--api-version=2", "--accept-multiclient", "--log-dest=var/dlv-imp-test.log",
			"exec",
			ex, "--", "imp", "--log.level=DEBUG", "--log.colorMode=always")
	} else {
		cmd = exec.Command(ex, "imp", "--log.level=DEBUG", "--log.colorMode=always")
	}
	cmd.Env = []string{
		"BIFROEST_IMP_ACCESS_TOKEN=" + tokenHex,
	}
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return failf("cannot create stdin pipe: %w", err)
	}
	defer common.IgnoreCloseError(stdin)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return failf("cannot create stdout pipe: %w", err)
	}
	defer common.IgnoreCloseError(stdin)
	cmdConn := net.NewConnectionFrom(stdout, stdin)

	adjustImpCmd(cmd)

	if err := cmd.Start(); err != nil {
		return failf("cannot start command: %w", err)
	}
	defer common.IgnoreError(cmd.Process.Kill)

	var iErr atomic.Pointer[error]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var i imp.Imp
		iSess, err := i.Connect(ctx, token, sess, cmdConn)
		if err != nil {
			log.WithError(err).Error("connect to imp failed")
			iErr.Store(&err)
			return
		}
		connectionId := uuid.New()

		rsp, err := iSess.Echo(connectionId, "hello imp!")
		if err != nil {
			log.WithError(err).Error("echo with imp failed")
			iErr.Store(&err)
			return
		}
		log.With("response", rsp).Info("got echo response")

		if err := iSess.Exit(connectionId, 0); err != nil {
			log.WithError(err).Error("exit of imp failed")
			iErr.Store(&err)
			return
		}
	}()

	if err := cmd.Wait(); err != nil {
		return failf("command execution failed: %w", err)
	}

	wg.Wait()
	if err := iErr.Load(); err != nil {
		return *err
	}

	return nil
}

type mockSession struct {
	id uuid.UUID
}

func (this *mockSession) Flow() configuration.FlowName {
	return "mock"
}

func (this *mockSession) Id() uuid.UUID {
	return this.id
}

func (this *mockSession) Info(ctx context.Context) (session.Info, error) {
	return nil, fmt.Errorf("not supported")
}

func (this *mockSession) AuthorizationToken(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (this *mockSession) EnvironmentToken(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (this *mockSession) HasPublicKey(context.Context, ssh.PublicKey) (bool, error) {
	return false, nil
}

func (this *mockSession) ConnectionInterceptor(context.Context) (session.ConnectionInterceptor, error) {
	return nil, fmt.Errorf("not supported")
}

func (this *mockSession) SetAuthorizationToken(context.Context, []byte) error {
	return fmt.Errorf("not supported")
}

func (this *mockSession) SetEnvironmentToken(context.Context, []byte) error {
	return fmt.Errorf("not supported")
}

func (this *mockSession) AddPublicKey(context.Context, ssh.PublicKey) error {
	return fmt.Errorf("not supported")
}

func (this *mockSession) DeletePublicKey(context.Context, ssh.PublicKey) error {
	return nil
}

func (this *mockSession) NotifyLastAccess(context.Context, net.Remote, session.State) (oldState session.State, err error) {
	return session.StateDisposed, nil
}

func (this *mockSession) Dispose(ctx context.Context) (bool, error) {
	return false, nil
}

func (this *mockSession) String() string {
	return this.Id().String()
}
