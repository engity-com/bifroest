package exec

import (
	"context"
	"fmt"
	goos "os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/internal/processidentity"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/sys"
)

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage common.Usage) {
	if !usage.IncludeExec() {
		return
	}

	c.AddCommand(cli.NewCommand[opts]().
		WithName("exec").
		WithDescription("Runs a given process with the given attributes (environment, working directory, ...).").
		WithCreateOptionsHandler(newOpts).
		WithVisible(false).
		WithHandler(handler),
	)
	registerLocalConPTYRelay(c)
}

func newOpts(context.Context) (opts, error) {
	return opts{
		WorkingDirectory:           common.WorkingDirectory(),
		Environment:                sys.EnvVars{},
		EncodedEnvironment:         goos.Getenv(execution.TargetEnvironmentEnvName),
		ExitCodeByConnectionIdPath: protocol.DefaultExitCodeByConnectionIdPath,
	}, nil
}

func handler(ctx context.Context, o opts) error {
	legacyState := false
	if o.StoreExitCodeForConnectionId && o.ExecutionId.IsZero() {
		if o.ConnectionId.IsZero() {
			return errors.System.Newf("--executionId is required with --storeExitCodeForConnectionId if --connectionId is not set")
		}
		// Older masters used the connection ID as the execution state ID.
		legacyState = true
		o.ExecutionId = o.ConnectionId
	}
	stateDirectory := o.ExitCodeByConnectionIdPath
	if !legacyState {
		stateDirectory = filepath.Join(stateDirectory, execution.StateDirectoryName)
	}
	if o.Environment == nil {
		o.Environment = make(map[string]string)
	}

	exit := func(exitCode int) error {
		if !o.ExecutionId.IsZero() && o.StoreExitCodeForConnectionId {
			_ = goos.MkdirAll(stateDirectory, 0700)
			fn := executionStatePath(stateDirectory, o.ExecutionId, "")
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
			With("command", o.Command).
			Error()
		return exit(1)
	}
	if o.EncodedEnvironment != "" {
		decoded, err := execution.DecodeTargetEnvironment(o.EncodedEnvironment)
		if err != nil {
			return fail(errors.System.Newf("cannot decode target environment: %w", err))
		}
		decodedEnvironment := sys.EnvVars(decoded)
		decodedEnvironment.AddAllOf(o.Environment)
		o.Environment = decodedEnvironment
	}
	ensureExecPathEnvironment(o.Environment)

	if !o.ConnectionId.IsZero() {
		setExecEnvironment(o.Environment, connection.EnvName, o.ConnectionId.String())
	}
	if !o.ExecutionId.IsZero() {
		setExecEnvironment(o.Environment, execution.EnvName, o.ExecutionId.String())
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
	if !o.ExecutionId.IsZero() {
		_ = goos.MkdirAll(stateDirectory, 0700)
		pidFn = executionStatePath(stateDirectory, o.ExecutionId, ".pid")
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
		Dir:         o.WorkingDirectory,
		SysProcAttr: &syscall.SysProcAttr{},
		Stderr:      cli.StderrOfContext(ctx),
		Stdin:       cli.StdinOfContext(ctx),
		Stdout:      cli.StdoutOfContext(ctx),
		Args:        o.Command,
		Path:        o.Executable,
	}

	if cmd.Path == "" && len(cmd.Args) > 0 {
		cmd.Path = cmd.Args[0]
	}
	var err error
	if cmd.Path, err = resolveExecPath(cmd.Path, cmd.Dir, o.Environment); err != nil {
		return fail(err)
	}
	cmd.Env = (sys.EnvVars(o.Environment)).Strings()

	if err := enrichExecCmd(&cmd, &o); err != nil {
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
	signal.Notify(sigs, execSignalsToForward()...)

	if err = cmd.Start(); err != nil {
		signal.Stop(sigs)
		_ = supervisor.Cleanup()
		return fail(err)
	}
	if !o.ExecutionId.IsZero() && !legacyState {
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
	identity, err := processidentity.Get(pid)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %s", pid, identity), nil
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
