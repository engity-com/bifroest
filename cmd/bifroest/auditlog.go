package main

import (
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/management"
)

var _ = registerCommand(func(app *kingpin.Application) {
	management.RegisterAuditlogCommands(app, loadManagementConfiguration, goos.Stdout, true)
})
