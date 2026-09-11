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
	var conf configuration.Ref
	cmd := app.Command("run", "Runs the service.").
		Action(func(*kingpin.ParseContext) error {
			return doRun(conf)
		})
	registerConfigurationFlag(cmd, &conf)
	return app
}

func doRun(conf configuration.Ref) error {
	return doRunDefault(conf)
}
