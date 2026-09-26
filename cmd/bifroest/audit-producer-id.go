package main

import (
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type auditProducerIdOpts struct {
	configuration configuration.Ref
	auditlog      configuration.AuditlogName
}

func registerAuditProducerIdCmd(parent *kingpin.CmdClause) {
	opts := auditProducerIdOpts{}
	cmd := parent.Command("producer-id", "Print the producer ID from a configured local audit signing key.").
		Action(func(*kingpin.ParseContext) error { return doAuditProducerId(&opts, goos.Stdout) })
	registerConfigurationFlag(cmd, &opts.configuration)
	cmd.Arg("auditlogName", "Configured auditlog whose signing identity to inspect.").Required().SetValue(&opts.auditlog)
}

func doAuditProducerId(opts *auditProducerIdOpts, output io.Writer) error {
	if opts == nil || output == nil {
		return fmt.Errorf("missing audit producer ID options or output")
	}
	configured, err := findConfiguredAuditlog(opts.configuration.Get(), opts.auditlog)
	if err != nil {
		return err
	}
	if !configured.Enabled && !configured.Recording.Enabled {
		return fmt.Errorf("auditlog %q and its Recording are disabled", configured.Name)
	}
	privateKey, err := loadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return fmt.Errorf("cannot load identity of auditlog %q: %w", configured.Name, err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		return fmt.Errorf("cannot use identity of auditlog %q: %w", configured.Name, err)
	}
	_, err = fmt.Fprintln(output, identity.ProducerId())
	return err
}
