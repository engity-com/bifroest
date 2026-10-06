package main

import (
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

var _ = registerCommand(func(app *kingpin.Application) {
	management.RegisterFlowCommands(app, func(path string) (*configuration.Configuration, error) {
		if path == "" {
			path = defaultConfigurationRef
		}
		var ref configuration.Ref
		if err := ref.Set(path); err != nil {
			return nil, err
		}
		return ref.Get(), nil
	}, goos.Stdout, false, true)
})
