package main

import "github.com/alecthomas/kingpin/v2"

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("key", "Generate, export and import SSH keys.")

	registerKeyGenerateCmd(cmd)
	registerKeyExportCmd(cmd)
	registerKeyImportCmd(cmd)
})
