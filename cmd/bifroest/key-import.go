package main

import "github.com/alecthomas/kingpin/v2"

func registerKeyImportCmd(parent *kingpin.CmdClause) {
	cmd := parent.Command("import", "Import trusted SSH public key material.")

	registerKeyImportCaCmd(cmd)
	registerKeyImportHostCmd(cmd)
}
