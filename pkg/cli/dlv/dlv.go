//go:build embedded_dlv

package dlv

import (
	"context"
	"fmt"
	"net"
	goos "os"
	"os/signal"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/echocat/cli4g"
	"github.com/echocat/slf4g"
	"github.com/go-delve/delve/service"
	"github.com/go-delve/delve/service/debugger"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/go-delve/delve/service/rpccommon"

	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/debug"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Addr string   `flag:"addr" placeholder:"[<host>]:<port>" description:"Address to bind to."`
	Wait bool     `flag:"wait" description:"By default the process continue to start without waiting for a remote debugger to attach. If this is provided, the target process wait to start for the first remote debugger being attached/connected."`
	Args []string `argument:"args" description:"The actual target arguments to run the bifroest binary with."`
}

func newOpts(context.Context) (opts, error) {
	return opts{
		fmt.Sprintf(":%d", debug.DlvPort),
		false,
		nil,
	}, nil
}

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[opts]("dlv", "Runs a command of this binary with Delve.").
			WithProfiles(cliCommon.ProfileExecutable).
			WithVisible(false).
			WithCreateOptionsHandler(newOpts).
			WithHandler(handler),
	}
}

func handler(_ context.Context, o opts) (rErr error) {
	fail := func(err error) error {
		return errors.System.Newf("cannot create delve instance: %v", err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	ln, err := net.Listen("tcp", o.Addr)
	if err != nil {
		return failf("cannot start to listen to %s: %w", o.Addr, err)
	}
	// defer common.IgnoreCloseError(ln)

	fn, err := goos.Executable()
	if err != nil {
		return failf("cannot get current executable: %w", err)
	}
	args := append([]string{fn}, o.Args...)

	disconnectChan := make(chan struct{})

	server := rpccommon.NewServer(&service.Config{
		Listener:       ln,
		ProcessArgs:    args,
		AcceptMulti:    true,
		APIVersion:     2,
		DisconnectChan: disconnectChan,
		Debugger: debugger.Config{
			WorkingDir:     ".",
			Backend:        "default",
			Foreground:     true,
			ExecuteKind:    debugger.ExecutingExistingFile,
			CheckGoVersion: true,
		},
	})

	if err := server.Run(); err != nil {
		return fail(err)
	}

	field := reflect.ValueOf(server).Elem().FieldByName("debugger")
	dbg := *reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Interface().(**debugger.Debugger)
	pid := dbg.ProcessPid()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	exitCodeChan := make(chan int, 1)
	go func() {
		ec, err := waitForDlvTargetProcess(ctx, pid)
		if err != nil {
			errChan <- err
			return
		}

		exitCodeChan <- ec
	}()

	defer common.KeepError(&rErr, server.Stop)

	exitChan := make(chan struct{})
	defer close(exitChan)
	sigs := make(chan goos.Signal, 1)
	signal.Notify(sigs)
	go func() {
		for {
			select {
			case <-exitChan:
				return
			case raw := <-sigs:
				scs, ok := raw.(syscall.Signal)
				if !ok {
					continue
				}
				sig := sys.Signal(scs)
				_ = sig.SendToPid(pid)
			}
		}
	}()

	if !o.Wait {
		lnAddr := ln.Addr().String()
		dial, err := net.Dial("tcp", lnAddr)
		if err != nil {
			log.WithError(err).
				With("addr", lnAddr).
				Warn("can't do initial connect")
			return
		}
		client := rpc2.NewClientFromConn(dial)
		_ = client.Disconnect(true)
	}

	select {
	case err := <-errChan:
		return err
	case exitCode := <-exitCodeChan:
		goos.Exit(exitCode)
		return nil
	case <-disconnectChan:
		return nil
	}
}
