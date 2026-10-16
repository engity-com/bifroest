package audit

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type mergeOptions struct {
	common.ExecutableConfigurationOpts
	OutputOpts
	DecryptionIdentityFilesOpts
	TrustAnchorsOpts
	common.WithSensitiveOpts
	configuration.AuditlogNamesOpts
}

type managementMergeOptions struct {
	configuration.AuditlogNamesOpts
	common.WithSensitiveOpts
}

func registerMerge(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(
		cli.NewCommand[managementMergeOptions]("merge", "Merge verified audit journals chronologically as JSON Lines.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementMerge),
	)
	parent.AddCommand(
		cli.NewCommand[mergeOptions]("merge", "Merge verified audit journals chronologically as JSON Lines.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleMerge),
	)
}

func handleManagementMerge(ctx context.Context, opts managementMergeOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Audit == nil {
		return fmt.Errorf("management audit repository is unavailable")
	}
	names := make([]configuration.AuditlogName, 0, len(opts.Auditlogs))
	for _, text := range opts.Auditlogs {
		name := configuration.AuditlogName(text)
		if err := name.Validate(); err != nil {
			return err
		}
		names = append(names, name)
	}
	return access.Audit.Export(ctx, names, opts.WithSensitive,
		audit.RecordOrderChronological, cli.StdoutOfContext(ctx))
}

func handleMerge(ctx context.Context, opts mergeOptions) error {
	names := make([]configuration.AuditlogName, 0, len(opts.Auditlogs))
	for _, raw := range opts.Auditlogs {
		name := configuration.AuditlogName(raw)
		if err := name.Validate(); err != nil {
			return err
		}
		names = append(names, name)
	}
	conf, err := common.ResolveConfiguration(ctx, opts)
	if err != nil {
		return err
	}
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if conf != nil {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return runRemoteAudit(ctx, target, remoteAuditOptions{
			Operation: remoteMerge, Names: names, TrustAnchors: opts.ExpectedProducerIds,
			IdentityFiles: opts.DecryptionIdentityFiles,
			Output:        opts.Output, Force: opts.Force, WithSensitive: opts.WithSensitive,
			Format: format.Text,
		}, cli.StdoutOfContext(ctx))
	}
	configured := make([]*configuration.Auditlog, 0, len(opts.Auditlogs))
	for _, name := range names {
		selected, err := FindConfigured(conf, name)
		if err != nil {
			return err
		}
		configured = append(configured, selected)
	}
	if len(configured) == 0 {
		return fmt.Errorf("at least one auditlog name is required")
	}
	expectedIDs, err := ParseAuditTrustAnchors(opts.ExpectedProducerIds, configured)
	if err != nil {
		return err
	}
	identities := opts.DecryptionIdentityFiles
	if !opts.WithSensitive {
		identities = nil
	}
	sources := make([]audit.JournalSource, 0, len(configured))
	for _, selected := range configured {
		source, err := configuredAuditJournalSource(selected, identities, expectedIDs[selected.Name])
		if err != nil {
			return err
		}
		source.WithSensitive = opts.WithSensitive
		sources = append(sources, source)
	}
	output, err := CanonicalAuditOutput(opts.Output)
	if err != nil {
		return err
	}
	stdout := cli.StdoutOfContext(ctx)
	validate := func() error {
		return EnsureAuditDestinationSafe(output, stdout, conf.Filename, conf, opts.DecryptionIdentityFiles)
	}
	if err := validate(); err != nil {
		return err
	}
	verified, err := audit.VerifyLiveJournals(ctx, sources)
	if err != nil {
		return err
	}
	return writeAuditOutput(output, opts.Force, stdout, verified, audit.RecordOrderChronological, validate)
}
