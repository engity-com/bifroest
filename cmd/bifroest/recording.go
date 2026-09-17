package main

import "github.com/alecthomas/kingpin/v2"

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("recording", "Inspect and export session Recording artifacts.")
	registerRecordingInspectCmd(cmd)
	registerRecordingExportCmd(cmd)
})
