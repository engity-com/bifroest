package main

import (
	"context"
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

type auditMergeOpts struct {
	configuration           configuration.Ref
	configurationPath       string
	auditlogs               []string
	output                  string
	force                   bool
	decryptionIdentityFiles []string
	expectedProducerIds     []string
	withSensitive           bool
	commandRoot             string
}

var remoteAuditMergeOpts = map[string]*auditMergeOpts{}

func registerAuditMergeCmd(parent *kingpin.CmdClause) {
	opts := auditMergeOpts{output: "-"}
	opts.commandRoot = parent.FullCommand()
	remoteAuditMergeOpts[parent.FullCommand()] = &opts
	cmd := management.AuditArtifactCommand(parent, "merge").
		Action(func(*kingpin.ParseContext) error { return doAuditMerge(&opts, goos.Stdout) })
	cmd.Flag("configuration", "Configuration file (defaults to "+defaultConfigurationRef+").").Short('c').StringVar(&opts.configurationPath)
	registerAuditOutputFlags(cmd, &opts.output, &opts.force)
	registerAuditDecryptionIdentityFlags(cmd, &opts.decryptionIdentityFiles)
	registerAuditTrustAnchorFlags(cmd, &opts.expectedProducerIds)
	registerAuditSensitiveFlag(cmd, &opts.withSensitive)
	cmd.Arg("auditlogName", "Configured auditlogs to merge.").Required().StringsVar(&opts.auditlogs)
}

func doAuditMerge(opts *auditMergeOpts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if format := selectedAuditFormat(opts.commandRoot, ""); format != management.FormatTable {
		return fmt.Errorf("audit merge has a fixed JSON Lines output; use auditlog events --format=%s for structured views", format)
	}
	configured := make([]*configuration.Auditlog, 0, len(opts.auditlogs))
	if opts.configurationPath != "" || len(opts.configuration.Get().Auditlogs) == 0 {
		path := opts.configurationPath
		if path == "" {
			path = defaultConfigurationRef
		}
		if err := opts.configuration.Set(path); err != nil {
			return err
		}
	}
	conf := opts.configuration.Get()
	for _, rawName := range opts.auditlogs {
		name := configuration.AuditlogName(rawName)
		if err := name.Validate(); err != nil {
			return err
		}
		selected, err := findConfiguredAuditlog(conf, name)
		if err != nil {
			return err
		}
		configured = append(configured, selected)
	}
	expectedProducerIds, err := parseAuditTrustAnchors(opts.expectedProducerIds, configured)
	if err != nil {
		return err
	}
	sources := make([]audit.JournalSource, 0, len(configured))
	identities := opts.decryptionIdentityFiles
	if !opts.withSensitive {
		identities = nil
	}
	for _, selected := range configured {
		source, err := configuredAuditJournalSource(selected, identities, expectedProducerIds[selected.Name])
		if err != nil {
			return err
		}
		source.WithSensitive = opts.withSensitive
		sources = append(sources, source)
	}
	output, err := canonicalAuditOutput(opts.output)
	if err != nil {
		return err
	}
	validate := func() error {
		return ensureAuditDestinationSafe(output, stdout, opts.configuration.GetFilename(), conf, opts.decryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	verification, err := audit.VerifyLiveJournals(context.Background(), sources)
	if err != nil {
		return err
	}
	return writeAuditOutput(output, opts.force, stdout, verification, audit.RecordOrderChronological, validate)
}
