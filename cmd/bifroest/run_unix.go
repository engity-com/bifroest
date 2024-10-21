//go:build unix

package main

import (
	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
)

const (
	defaultConfigurationRef = "/etc/engity/bifroest/configuration.yaml"
)

func configureRunCmd(app *kingpin.Application) *kingpin.Application {
	var conf configuration.ConfigurationRef
	cmd := app.Command("run", "Runs the service.").
		Action(func(*kingpin.ParseContext) error {
			return doRun(conf)
		})
	cmd.Flag("configuration", "Configuration which should be used to serve the service. Default: "+defaultConfigurationRef).
		Short('c').
		Default(defaultConfigurationRef).
		PlaceHolder("<path>").
		SetValue(&conf)
	return app
}

func doRun(conf configuration.ConfigurationRef) error {
	return doRunDefault(conf)
}
