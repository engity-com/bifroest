package main

import (
	"context"
	stderrors "errors"
	"fmt"
	goos "os"
	"os/signal"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/audit"
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/recording"
	"github.com/engity-com/bifroest/pkg/logging"
	"github.com/engity-com/bifroest/pkg/managementclient"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g/native"
)

var (
	errRemoteHandled = stderrors.New("remote command already handled")
)

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

	ctx, stop := signal.NotifyContext(context.Background(), goos.Interrupt)
	defer stop()

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
		switch ctx.SelectedCommand.FullCommand() {
		case "auditlog events":
			if audit.remoteAuditEventsOpts != nil && (audit.remoteAuditEventsOpts.WithSensitive || audit.remoteAuditEventsOpts.ExpectedProducerID != "") {
				if err := audit.doRemoteAuditEvents(ctx, target, audit.remoteAuditEventsOpts, goos.Stdout); err != nil {
					return err
				}
				return errRemoteHandled
			}
		case "audit verify", "audit export", "audit decrypt", "audit merge", "audit producer-id",
			"auditlog verify", "auditlog export", "auditlog decrypt", "auditlog merge", "auditlog producer-id":
			if err := audit.doRemoteAuditCommand(ctx, target, ctx.SelectedCommand.FullCommand(), goos.Stdout); err != nil {
				return err
			}
			return errRemoteHandled
		case "recording verify", "recording export", "recording play":
			if err := recording.doRemoteRecordingCommand(ctx, target, ctx.SelectedCommand.FullCommand(), goos.Stdout); err != nil {
				return err
			}
			return errRemoteHandled
		}
		if err := managementclient.Run(ctx, managementclient.Target{
			Host: target.RawHost, User: target.User, Port: target.Port, ExplicitPort: target.ExplicitPort,
		}, args, goos.Stdout); err != nil {
			return err
		}
		return errRemoteHandled
	})

	cli.Register(ctx, app, UsageExecutable, versionV)

	if _, err := app.Parse(args); err != nil {
		if stderrors.Is(err, errRemoteHandled) {
			return
		}
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}
