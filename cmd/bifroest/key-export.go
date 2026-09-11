package main

import "github.com/alecthomas/kingpin/v2"

func registerKeyExportCmd(parent *kingpin.CmdClause) {
	cmd := parent.Command("export", "Export SSH public key material.")

	registerKeyExportPublicCmd(cmd)
	registerKeyExportCaCmd(cmd)
	registerKeyExportHostCmd(cmd)
}
