package main

import (
	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/engity/pam-oidc/pkg/service"
	"os"
)

func registerRunCmd(app *kingpin.Application) {
	cmd := app.Command("run", "Run the service.").
		Action(func(*kingpin.ParseContext) error {
			return doRun()
		})
	cmd.Flag("configuration", `Configuration which should be used to serve the service.`).
		Short('c').
		Default(configurationRef.String()).
		SetValue(&configurationRef)
}

func doRun() error {
	svc := service.Service{
		Configuration: *configurationRef.Get(),
	}

	fail := func(err error) error {
		log.Error(err)
		os.Exit(1)
		return nil
	}

	if err := svc.Run(); err != nil {
		return fail(err)
	}

	return nil
}
