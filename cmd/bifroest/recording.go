package main

import "github.com/alecthomas/kingpin/v2"

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("recording", "Verify, inspect and export session Recording artifacts.")
	registerRecordingInspectCmd(cmd)
	registerRecordingVerifyCmd(cmd)
	registerRecordingExportCmd(cmd)
})
