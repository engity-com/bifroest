package main

import (
	"context"
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type auditMergeOpts struct {
	configuration           configuration.Ref
	auditlogs               []string
	output                  string
	force                   bool
	decryptionIdentityFiles []string
}

func registerAuditMergeCmd(parent *kingpin.CmdClause) {
	opts := auditMergeOpts{output: "-"}
	cmd := parent.Command("merge", "Merge verified audit journals chronologically as JSON Lines.").
		Action(func(*kingpin.ParseContext) error { return doAuditMerge(&opts, goos.Stdout) })
	registerConfigurationFlag(cmd, &opts.configuration)
	registerAuditOutputFlags(cmd, &opts.output, &opts.force)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	cmd.Arg("auditlogName", "Configured auditlogs to merge.").Required().StringsVar(&opts.auditlogs)
}

func doAuditMerge(opts *auditMergeOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	configured := make([]*configuration.Auditlog, 0, len(opts.auditlogs))
	sources := make([]audit.JournalSource, 0, len(opts.auditlogs))
	for _, rawName := range opts.auditlogs {
		name := configuration.AuditlogName(rawName)
		if err := name.Validate(); err != nil {
			return err
		}
		selected, err := findConfiguredAuditlog(opts.configuration.Get(), name)
		if err != nil {
			return err
		}
		configured = append(configured, selected)
		source, err := configuredAuditJournalSource(selected, opts.decryptionIdentityFiles)
		if err != nil {
			return err
		}
		sources = append(sources, source)
	}
	output, err := canonicalAuditOutput(opts.output)
	if err != nil {
		return err
	}
	if err := ensureAuditOutputSafe(output, configured); err != nil {
		return err
	}
	if err := ensureBootstrapOutputIsNotPrivateKey(output, opts.decryptionIdentityFiles...); err != nil {
		return err
	}
	verification, err := audit.VerifyJournals(context.Background(), sources)
	if err != nil {
		return err
	}
	if err := ensureAuditOutputSafe(output, configured); err != nil {
		return err
	}
	if err := ensureBootstrapOutputIsNotPrivateKey(output, opts.decryptionIdentityFiles...); err != nil {
		return err
	}
	return writeAuditOutput(output, opts.force, stdout, verification, audit.RecordOrderChronological)
}
