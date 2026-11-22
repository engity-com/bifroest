package main

import (
	"context"
	"errors"
	goos "os"
	"os/signal"
	"strings"

	clibase "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"

	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/service"
	bftest "github.com/engity-com/bifroest/pkg/test"
)

func main() {
	if err := run(); err != nil {
		if !errorWasReported(err) {
			log.WithError(err).Error("execution failed")
		}
		goos.Exit(exitCode(err))
	}
}

// A joined cleanup/output failure is not silenced merely because another error
// in the chain already has a complete policy-test report.
func errorWasReported(err error) bool {
	if err == nil {
		return false
	}
	if command, ok := err.(*bftest.CommandError); ok {
		return command.Reported
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !errorWasReported(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return errorWasReported(wrapped.Unwrap())
	}
	return false
}

func run() (resultErr error) {
	native.DefaultProvider.Consumer = consumer.NewWriter(goos.Stderr)
	application, err := cli.NewApplication[opts](versionV, "SSH server and gateway for standard SSH clients: OIDC Device Authorization, Docker/Kubernetes sessions, verifiable audit and recording.", service.Run).
		WithInitializeHandler(configureExecutableLogging).
		WithFallbackToStdio(true).
		Create()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, application.Close()) }()
	target, args, err := parseManagementTarget(goos.Args[1:])
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), goos.Interrupt)
	defer stop()

	profile := common.ProfileExecutable
	if target != nil {
		profile = common.ProfileRemote
		ctx = common.ContextWithRemoteTarget(ctx, management.Target{
			Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort,
		})
	}
	err = application.ParseAndExecute(ctx, &clibase.ParseOpts{
		Profiles: []string{profile},
	}, args...)
	if err != nil && target == nil && policyTestRequested(args) {
		var commandErr *bftest.CommandError
		if !errors.As(err, &commandErr) {
			return &bftest.CommandError{Code: 2, Cause: err}
		}
	}
	return err
}

func policyTestRequested(args []string) bool {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "--log.level", "--log.format", "--log.colorMode":
			index++
			continue
		}
		if strings.HasPrefix(arg, "--log.") && strings.Contains(arg, "=") {
			continue
		}
		return arg == "test"
	}
	return false
}

func exitCode(err error) int {
	var commandErr *bftest.CommandError
	if errors.As(err, &commandErr) && (commandErr.Code == 1 || commandErr.Code == 2) {
		return commandErr.Code
	}
	return 1
}
