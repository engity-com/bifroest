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
	"github.com/engity-com/bifroest/pkg/managementclient"
)

func main() {
	if err := run(); err != nil {
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}

func run() (resultErr error) {
	native.DefaultProvider.Consumer = consumer.NewWriter(goos.Stderr)
	ctx, stop := signal.NotifyContext(context.Background(), goos.Interrupt)
	defer stop()
	ctx = clibase.ContextWithStdio(ctx, goos.Stdin, goos.Stdout, goos.Stderr)
	applications, err := cli.NewApplications(versionV)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, applications.Close()) }()
	ctx = common.ContextWithManagementApplication(ctx, applications.Management)
	target, args, err := parseManagementTarget(goos.Args[1:])
	if err != nil {
		return err
	}
	if target != nil {
		if len(args) == 0 || !supportsRemoteManagementCommand(args[0]) {
			return fmt.Errorf("command %q does not support remote execution", args)
		}
		ctx = common.ContextWithRemoteTarget(ctx, managementclient.Target{
			Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort,
		})
	}
	return applications.Executable.ParseAndExecute(ctx, nil, args...)
}
