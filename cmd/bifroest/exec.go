package main

import (
	goos "os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

var _ = registerCommand(func(app *kingpin.Application) {
	opts := execOpts{
		workingDirectory: workingDirectory(),
		environment:      sys.EnvVars{},
	}

	cmd := app.Command("exec", "Runs a given process with the given attributes (environment, working directory, ...).").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doExec(&opts)
		})
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
	cmd.Arg("command", "Command to execute.").
		Required().
		StringsVar(&opts.argv)

	registerExecCmdFlags(cmd, &opts)
})

func doExec(opts *execOpts) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
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
		return failf("cannot apply execution parameters to %v: :%w", cmd.Args, err)
	}

	sigs := make(chan goos.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs)

	go func() {
		for {
			sig, ok := <-sigs
			if !ok {
				return
			}
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Run()
	var eErr *exec.ExitError
	if errors.As(err, &eErr) {
		goos.Exit(eErr.ExitCode())
		return nil
	} else if err != nil {
		return fail(err)
	} else {
		return nil
	}
}
