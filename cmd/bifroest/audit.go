package main

import (
	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/management"
)

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

func selectedAuditFormat(root, ownFormat string) management.Format {
	if root == "auditlog" && remoteAuditEventsOpts != nil && remoteAuditEventsOpts.Format != "" {
		return management.Format(remoteAuditEventsOpts.Format)
	}
	if ownFormat != "" {
		return management.Format(ownFormat)
	}
	return management.FormatTable
}
