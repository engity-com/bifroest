package main

import "github.com/alecthomas/kingpin/v2"

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("audit", "Verify, decrypt, export and merge audit journals.")
	registerAuditVerifyCmd(cmd)
	registerAuditDecryptCmd(cmd)
	registerAuditExportCmd(cmd)
	registerAuditMergeCmd(cmd)
})
