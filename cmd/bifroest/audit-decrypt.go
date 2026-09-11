package main

import (
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"
)

func registerAuditDecryptCmd(parent *kingpin.CmdClause) {
	opts := auditExportOpts{output: "-"}
	cmd := parent.Command("decrypt", "Decrypt an audit journal to verified JSON Lines.").
		Action(func(*kingpin.ParseContext) error { return doAuditDecrypt(&opts, goos.Stdout) })
	registerConfigurationFlag(cmd, &opts.configuration)
	registerAuditOutputFlags(cmd, &opts.output, &opts.force)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	cmd.Arg("auditlogName", "Configured auditlog to decrypt.").Required().SetValue(&opts.auditlog)
}

func doAuditDecrypt(opts *auditExportOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	return doAuditExport(opts, stdout)
}
