package main

import (
	"fmt"
	goos "os"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/logging"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g/native"
)

var (
	registerCommands []func(*kingpin.Application)
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
		return fmt.Errorf("remote execution of %q is not available yet", ctx.SelectedCommand.FullCommand())
	})

	for _, rc := range registerCommands {
		rc(app)
	}

	if _, err := app.Parse(args); err != nil {
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}
