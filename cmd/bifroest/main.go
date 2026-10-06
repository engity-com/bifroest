package main

import (
	"context"
	stderrors "errors"
	"fmt"
	goos "os"
	"os/signal"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/logging"
	"github.com/engity-com/bifroest/pkg/managementclient"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g/native"
)

var (
	registerCommands []func(*kingpin.Application)
	errRemoteHandled = stderrors.New("remote command already handled")
)

func registerCommand(rc func(*kingpin.Application)) func(*kingpin.Application) {
	registerCommands = append(registerCommands, rc)
	return rc
}

func main() {
	target, args, err := parseManagementTarget(goos.Args[1:])
	if err != nil {
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
	app := kingpin.New("bifroest", "SSH server which provides authorization and authentication via OpenID Connect and classic mechanisms to access a real host or a dedicated Docker container.").
		UsageWriter(goos.Stderr).
		ErrorWriter(goos.Stderr).
		Terminate(func(i int) {
			code := max(i, 1)
			goos.Exit(code)
		})

	logging.ConfigureLoggingForFlags(app, native.DefaultProvider)
	app.PreAction(func(ctx *kingpin.ParseContext) error {
		if target == nil {
			return nil
		}
		if ctx.SelectedCommand == nil || !supportsRemoteManagementCommand(ctx.SelectedCommand.FullCommand()) {
			command := ""
			if ctx.SelectedCommand != nil {
				command = ctx.SelectedCommand.FullCommand()
			}
			return fmt.Errorf("command %q does not support remote execution", command)
		}
		remoteCtx, stop := signal.NotifyContext(context.Background(), goos.Interrupt)
		defer stop()
		switch ctx.SelectedCommand.FullCommand() {
		case "audit verify", "audit export", "audit decrypt", "audit merge", "audit producer-id":
			if err := doRemoteAuditCommand(remoteCtx, target, ctx.SelectedCommand.FullCommand(), goos.Stdout); err != nil {
				return err
			}
			return errRemoteHandled
		case "recording verify", "recording export", "recording play":
			if err := doRemoteRecordingCommand(remoteCtx, target, ctx.SelectedCommand.FullCommand(), goos.Stdout); err != nil {
				return err
			}
			return errRemoteHandled
		}
		if err := managementclient.Run(remoteCtx, managementclient.Target{
			Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort,
		}, args, goos.Stdout); err != nil {
			return err
		}
		return errRemoteHandled
	})

	for _, rc := range registerCommands {
		rc(app)
	}

	if _, err := app.Parse(args); err != nil {
		if stderrors.Is(err, errRemoteHandled) {
			return
		}
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}
