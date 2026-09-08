package main

import (
	"fmt"
	goos "os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

var _ = registerCommand(func(app *kingpin.Application) {
	opts := execOpts{
		workingDirectory:           workingDirectory(),
		environment:                sys.EnvVars{},
		exitCodeByConnectionIdPath: protocol.DefaultExitCodeByConnectionIdPath,
	}

	cmd := app.Command("exec", "Runs a given process with the given attributes (environment, working directory, ...).").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doExec(&opts)
		})
	cmd.Flag("connectionId", "Connection ID this execution is connected to.").
		Short('c').
		PlaceHolder("<connectionId>").
		SetValue(&opts.connectionId)
	cmd.Flag("executionId", "Unique ID of this execution.").
		PlaceHolder("<executionId>").
		SetValue(&opts.executionId)
	cmd.Flag("workingDir", "Directory to start in.").
		Short('d').
		Default(opts.workingDirectory).
		PlaceHolder("<path>").
		StringVar(&opts.workingDirectory)
	cmd.Flag("executable", "Path to executable to be used. If not defined, first argument will be used.").
		Short('p').
		Default(opts.path).
		PlaceHolder("<path>").
		StringVar(&opts.path)
	cmd.Flag("env", "Environment variables to execute the process with.").
		Short('e').
		StringMapVar(&opts.environment)
	cmd.Flag("storeExitCodeForConnectionId", "Store this process' exit code under --exitCodeByConnectionIdPath; requires --executionId.").
		Short('x').
		BoolVar(&opts.storeExitCodeForConnectionId)
	cmd.Flag("exitCodeByConnectionIdPath", "Folder where exitCodes by their connectionId will be placed.").
		Default(opts.exitCodeByConnectionIdPath).
		PlaceHolder("<path>").
		StringVar(&opts.exitCodeByConnectionIdPath)
	cmd.Arg("command", "Command to execute.").
		Required().
		StringsVar(&opts.argv)

	registerExecCmdFlags(cmd, &opts)
})

func doExec(opts *execOpts) error {
	legacyState := false
	if opts.storeExitCodeForConnectionId && opts.executionId.IsZero() {
		if opts.connectionId.IsZero() {
			return errors.System.Newf("--executionId is required with --storeExitCodeForConnectionId if --connectionId is not set")
		}
		// Older masters used the connection ID as the execution state ID.
		legacyState = true
		opts.executionId = opts.connectionId
	}
	stateDirectory := opts.exitCodeByConnectionIdPath
	if !legacyState {
		stateDirectory = filepath.Join(stateDirectory, execution.StateDirectoryName)
	}
	if opts.environment == nil {
		opts.environment = make(map[string]string)
	}

	exit := func(exitCode int) error {
		if !opts.executionId.IsZero() && opts.storeExitCodeForConnectionId {
			_ = goos.MkdirAll(stateDirectory, 0700)
			fn := executionStatePath(stateDirectory, opts.executionId, "")
			if err := writeFileAtomically(fn, []byte(strconv.Itoa(exitCode))); err != nil {
				log.WithError(err).
					With("exitCode", exitCode).
					With("storage", fn).
					Warn("cannot propagate exitCode")
			}
		}

		return nil
	}
	fail := func(err error) error {
		log.WithError(err).
			With("command", opts.argv).
			Error()
		return exit(1)
	}

	if !opts.connectionId.IsZero() {
		opts.environment[connection.EnvName] = opts.connectionId.String()
	}
	if !opts.executionId.IsZero() {
		opts.environment[execution.EnvName] = opts.executionId.String()
	}
	var pidFn string
	registerStatePid := func(pid int) error {
		identity, identityErr := processIdentity(pid)
		if identityErr != nil {
			return errors.System.Newf("cannot identify process %d: %w", pid, identityErr)
		}
		if err := writeFileAtomically(pidFn, []byte(identity)); err != nil {
			return errors.System.Newf("cannot register process %d in %s: %w", pid, pidFn, err)
		}
		return nil
	}
	if !opts.executionId.IsZero() {
		_ = goos.MkdirAll(stateDirectory, 0700)
		pidFn = executionStatePath(stateDirectory, opts.executionId, ".pid")
		defer func() { _ = goos.Remove(pidFn) }()
		var err error
		if legacyState {
			err = registerStatePid(goos.Getpid())
		} else {
			var identity string
			if identity, err = processIdentity(goos.Getpid()); err == nil {
				err = writeFileAtomically(pidFn, []byte(execution.StateStartingMarker+" "+identity))
			}
		}
		if err != nil {
			return fail(err)
		}
	}

	cmd := exec.Cmd{
		Dir:         opts.workingDirectory,
		SysProcAttr: &syscall.SysProcAttr{},
		Env:         (sys.EnvVars(opts.environment)).Strings(),
		Stderr:      goos.Stderr,
		Stdin:       goos.Stdin,
		Stdout:      goos.Stdout,
		Args:        opts.argv,
		Path:        opts.path,
	}

	if cmd.Path == "" && len(cmd.Args) > 0 {
		cmd.Path = cmd.Args[0]
	}
	var err error
	if cmd.Path, err = exec.LookPath(cmd.Path); err != nil {
		return fail(err)
	}

	if err := enrichExecCmd(&cmd, opts); err != nil {
		return fail(err)
	}
	supervisor, err := newExecProcessSupervisor()
	if err != nil {
		return fail(err)
	}
	if err := supervisor.Prepare(&cmd); err != nil {
		_ = supervisor.Cleanup()
		return fail(err)
	}

	sigs := make(chan goos.Signal, 16)
	signal.Notify(sigs)

	if err = cmd.Start(); err != nil {
		signal.Stop(sigs)
		_ = supervisor.Cleanup()
		return fail(err)
	}
	if !opts.executionId.IsZero() && !legacyState {
		if err := registerStatePid(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			signal.Stop(sigs)
			_ = supervisor.Cleanup()
			return fail(err)
		}
	}
	if err := supervisor.Attach(&cmd); err != nil {
		_ = cmd.Process.Kill()
		waitErr := cmd.Wait()
		signal.Stop(sigs)
		_ = supervisor.Cleanup()
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exit(execExitCode(exitErr))
		}
		return fail(err)
	}
	signalDone := make(chan struct{})
	signalHandlerDone := make(chan struct{})
	go func() {
		defer close(signalHandlerDone)
		for {
			select {
			case <-signalDone:
				return
			case plain := <-sigs:
				select {
				case <-signalDone:
					return
				default:
				}
				scs, ok := plain.(syscall.Signal)
				if !ok {
					log.With("signal", plain).Warn("cannot forward unknown signal")
					continue
				}
				_ = signalExecCmd(&cmd, sys.Signal(scs))
			}
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigs)
	close(signalDone)
	<-signalHandlerDone
	if cleanupErr := supervisor.Cleanup(); cleanupErr != nil {
		log.WithError(cleanupErr).Warn("cannot clean up descendant processes")
	}
	var eErr *exec.ExitError
	if errors.As(err, &eErr) {
		return exit(execExitCode(eErr))
	} else if err != nil {
		return fail(err)
	} else {
		return exit(0)
	}
}

func processIdentity(pid int) (string, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return "", err
	}
	createdAt, err := p.CreateTime()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %d", pid, createdAt), nil
}

func executionStatePath(directory string, executionId execution.Id, suffix string) string {
	return filepath.Join(directory, executionId.String()+suffix)
}

func writeFileAtomically(path string, content []byte) (rErr error) {
	temporary, err := goos.CreateTemp(filepath.Dir(path), ".bifroest-execution-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = goos.Remove(temporaryPath) }()
	closed := false
	defer func() {
		if !closed {
			if err := temporary.Close(); rErr == nil {
				rErr = err
			}
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	return goos.Rename(temporaryPath, path)
}
