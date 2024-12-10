package main

import (
	goos "os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/internal/imp/protocol"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
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
	cmd.Flag("storeExitCodeForConnectionId", "If provided in the configured and --connectionId is present; under --exitCodeByConnectionIdPath the exitCode of this process will be stored.").
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
	exit := func(exitCode int) error {
		if !opts.connectionId.IsZero() && opts.storeExitCodeForConnectionId {
			_ = goos.MkdirAll(opts.exitCodeByConnectionIdPath, 0700)
			fn := filepath.Join(opts.exitCodeByConnectionIdPath, opts.connectionId.String())
			if err := goos.WriteFile(fn, []byte(strconv.Itoa(exitCode)), 0600); err != nil {
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

	sigs := make(chan goos.Signal, 1)
	defer func() {
		signal.Stop(sigs)
		close(sigs)
	}()
	signal.Notify(sigs)

	go func() {
		for {
			plain, ok := <-sigs
			if !ok {
				return
			}
			var bss sys.Signal
			scs, ok := plain.(syscall.Signal)
			if ok {
				bss = sys.Signal(scs)
			} else {
				bss = sys.SIGKILL
			}

			if p := cmd.Process; p != nil {
				_ = bss.SendToProcess(p)
			} else {
				switch bss {
				case sys.SIGTERM, sys.SIGINT:
					goos.Exit(126)
				}
			}
		}
	}()

	err = cmd.Run()
	var eErr *exec.ExitError
	if errors.As(err, &eErr) {
		return exit(eErr.ExitCode())
	} else if err != nil {
		return fail(err)
	} else {
		return exit(0)
	}
}
