package main

import "github.com/alecthomas/kingpin/v2"

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("audit", "Identify, verify, decrypt, export and merge audit journals.")
	registerAuditArtifactCommands(cmd)
})

func registerAuditArtifactCommands(cmd *kingpin.CmdClause) {
	registerAuditProducerIdCmd(cmd)
	registerAuditVerifyCmd(cmd)
	registerAuditDecryptCmd(cmd)
	registerAuditExportCmd(cmd)
	registerAuditMergeCmd(cmd)
}
