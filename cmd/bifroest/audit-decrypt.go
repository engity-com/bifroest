package main

import (
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"
)

func registerAuditDecryptCmd(parent *kingpin.CmdClause) {
	opts := auditExportOpts{output: "-"}
	cmd := parent.Command("decrypt", "Alias for audit export (verified JSON Lines).").
		Action(func(*kingpin.ParseContext) error { return doAuditDecrypt(&opts, goos.Stdout) })
	registerAuditExportFlags(cmd, &opts)
	cmd.Arg("auditlogName", "Configured auditlog, or optional label for an offline journal (default: default).").SetValue(&opts.auditlog)
}

func doAuditDecrypt(opts *auditExportOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	return doAuditExport(opts, stdout)
}
