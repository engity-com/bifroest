package main

import (
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
	app := kingpin.New("bifroest", "SSH server which provides authorization and authentication via OpenID Connect and classic mechanisms to access a real host or a dedicated Docker container.").
		UsageWriter(goos.Stderr).
		ErrorWriter(goos.Stderr).
		Terminate(func(i int) {
			code := max(i, 1)
			goos.Exit(code)
		})

	logging.ConfigureLoggingForFlags(app, native.DefaultProvider)

	for _, rc := range registerCommands {
		rc(app)
	}

	if _, err := app.Parse(goos.Args[1:]); err != nil {
		log.WithError(err).Error("execution failed")
		goos.Exit(1)
	}
}
