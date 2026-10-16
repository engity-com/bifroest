package main

import (
	"context"
	"errors"
	goos "os"
	"os/signal"

	clibase "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"

	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
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
	return application.ParseAndExecute(ctx, &clibase.ParseOpts{
		Profiles: []string{profile},
	}, args...)
}
