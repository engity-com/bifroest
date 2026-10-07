package merge

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	audit2 "github.com/engity-com/bifroest/pkg/cli/audit"
	. "github.com/engity-com/bifroest/pkg/cli/audit/common"
	"github.com/engity-com/bifroest/pkg/cli/audit/export"
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

type opts struct {
	configuration.Opts
	OutputOpts
	DecryptionIdentityFilesOpts
	TrustAnchorsOpts
	management.WithSensitiveOpts
	configuration.AuditlogNamesOpts
	commandRoot string
}

var remoteAuditMergeOpts = map[string]*opts{}

func Register(_ context.Context, c cli.ContainerRequirementSetters, _ Usage) {
	o.commandRoot = cmds.FullCommand()
	remoteAuditMergeOpts[cmds.FullCommand()] = &o

	c.AddCommand(cli.NewCommand[opts]().
		WithName("merge").
		WithDescription("Merge verified audit journals chronologically as JSON Lines.").
		WithHandler(handle),
	)
}

func handle(ctx context.Context, o opts) error {
	if format := audit2.selectedAuditFormat(o.commandRoot, ""); format != management.FormatTable {
		return fmt.Errorf("audit merge has a fixed JSON Lines output; use auditlog events --format=%s for structured views", format)
	}
	configured := make([]*configuration.Auditlog, 0, len(o.Auditlogs))
	for _, rawName := range o.Auditlogs {
		name := configuration.AuditlogName(rawName)
		if err := name.Validate(); err != nil {
			return err
		}
		selected, err := FindConfigured(&o.Configuration, name)
		if err != nil {
			return err
		}
		configured = append(configured, selected)
	}
	expectedProducerIds, err := audit2.parseAuditTrustAnchors(o.ExpectedProducerIds, configured)
	if err != nil {
		return err
	}
	sources := make([]audit.JournalSource, 0, len(configured))
	identities := o.DecryptionIdentityFiles
	if !o.WithSensitive {
		identities = nil
	}
	for _, selected := range configured {
		source, err := audit2.configuredAuditJournalSource(selected, identities, expectedProducerIds[selected.Name])
		if err != nil {
			return err
		}
		source.WithSensitive = o.WithSensitive
		sources = append(sources, source)
	}
	output, err := export.canonicalAuditOutput(o.Output)
	if err != nil {
		return err
	}
	validate := func() error {
		return export.ensureAuditDestinationSafe(output, stdout, o.configuration.GetFilename(), conf, o.DecryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	verification, err := audit.VerifyLiveJournals(context.Background(), sources)
	if err != nil {
		return err
	}
	return export.writeAuditOutput(output, o.Force, stdout, verification, audit.RecordOrderChronological, validate)
}
