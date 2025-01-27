//go:build embedded_dlv

package main

import (
	"fmt"
	"net"
	goos "os"
	"os/signal"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/go-delve/delve/service"
	"github.com/go-delve/delve/service/debugger"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/go-delve/delve/service/rpccommon"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/debug"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var _ = registerCommand(func(app *kingpin.Application) {
	addr := fmt.Sprintf(":%d", debug.DlvPort)
	var wait bool
	var args []string

	cmd := app.Command("dlv", "Runs a command of this binary with Delve.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doDlv(addr, wait, args)
		})
	cmd.Flag("addr", "Address to bind to.").
		Default(addr).
		PlaceHolder("[<host>]:<port>").
		StringVar(&addr)
	cmd.Flag("wait", "By default the process continue to start without waiting for a remote debugger to attach. If this is provided, the target process wait to start for the first remote debugger being attached/connected.").
		BoolVar(&wait)
	cmd.Arg("args", "The actual target arguments to run the bifroest binary with.").
		StringsVar(&args)
})

func doDlv(addr string, wait bool, args []string) (rErr error) {
	fail := func(err error) error {
		return errors.System.Newf("cannot create delve instance: %v", err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return failf("cannot start to listen to %s: %w", addr, err)
	}
	defer common.IgnoreCloseError(ln)

	fn, err := goos.Executable()
	if err != nil {
		return failf("cannot get current executable: %w", err)
	}
	args = append([]string{fn}, args...)

	disconnectChan := make(chan struct{})

	server := rpccommon.NewServer(&service.Config{
		Listener:       ln,
		ProcessArgs:    args,
		AcceptMulti:    true,
		APIVersion:     2,
		DisconnectChan: disconnectChan,
		Debugger: debugger.Config{
			WorkingDir: ".",
			Backend:    "default",
			// Foreground:     true,
			ExecuteKind:    debugger.ExecutingExistingFile,
			CheckGoVersion: true,
			// Stdin:          "",
			// Stdout:         proc.OutputRedirect{File: goos.Stdout},
			// Stderr:         proc.OutputRedirect{File: goos.Stderr},
		},
	})

	if err := server.Run(); err != nil {
		return fail(err)
	}
	defer common.KeepError(&rErr, server.Stop)

	field := reflect.ValueOf(server).Elem().FieldByName("debugger")
	dbg := *reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Interface().(**debugger.Debugger)

	pid := dbg.ProcessPid()

	p, err := goos.FindProcess(pid)
	if err != nil {
		return failf("cannot find process with PID %d we want to debug: %w", pid, err)
	}

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
				if err := sig.SendToProcess(p); err != nil {
					log.WithError(err).With("pid", p.Pid).Warn("cannot send signal to process")
				}
			}
		}
	}()

	if !wait {
		lnAddr := ln.Addr().String()
		dial, err := net.Dial("tcp", lnAddr)
		if err != nil {
			return failf("cannot connect initially to %s: %w", lnAddr, err)
		}
		client := rpc2.NewClientFromConn(dial)
		_ = client.Disconnect(true)
	}

	ps, err := p.Wait()
	if err != nil {
		log.WithError(err).With("pid", pid).Error("try wait for process... FAILED!")
		return failf("cannot wait for process with PID %d: %w", pid, err)
	}
	ws := ps.Sys().(syscall.WaitStatus)

	if ws.Exited() {
		goos.Exit(ws.ExitStatus())
		return nil
	}

	if ws.Signaled() {
		return fmt.Errorf("process received with signal %v (%d)", ws.Signal(), ws.Signal())
	}

	if ws.Stopped() {
		return fmt.Errorf("process was stopped by signal %v (%d)", ws.StopSignal(), ws.StopSignal())
	}

	return nil
}
