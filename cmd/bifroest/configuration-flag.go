package main

import (
	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func registerConfigurationFlag(cmd *kingpin.CmdClause, target *configuration.Ref) {
	cmd.Flag("configuration", "Configuration which should be used. Default: "+defaultConfigurationRef).
		Short('c').
		Default(defaultConfigurationRef).
		PlaceHolder("<path>").
		SetValue(target)
}
