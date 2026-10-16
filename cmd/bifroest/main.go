package main

import (
	"context"
	"errors"
	"fmt"
	goos "os"
	"os/signal"

	clibase "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"

	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/service"
)

func main() {
	if err := run(); err != nil {
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}

func run() (resultErr error) {
	native.DefaultProvider.Consumer = consumer.NewWriter(goos.Stderr)
	application, err := cli.NewApplication[opts](versionV, "SSH server and gateway for standard SSH clients: OIDC Device Authorization, Docker/Kubernetes sessions, verifiable audit and recording.", service.Run).
		WithInitializeHandler(configureExecutableLogging).
		WithFallbackToStdio(true).
		WithCodec(configuration.NewCliCodec(true, true)).
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

	if target != nil {
		if len(args) == 0 || !supportsRemoteManagementCommand(args[0]) {
			return fmt.Errorf("command %q does not support remote execution", args)
		}
		ctx = common.ContextWithRemoteTarget(ctx, management.Target{
			Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort,
		})
	}
	return application.ParseAndExecute(ctx, &clibase.ParseOpts{
		Profiles: []string{common.ProfileExecutable},
	}, args...)
}
