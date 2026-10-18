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

func createMergeCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[managementMergeOptions]("merge", "Merge verified audit journals chronologically as JSON Lines.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementMerge),
		cli.NewCommand[mergeOptions]("merge", "Merge verified audit journals chronologically as JSON Lines.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleMerge),
		cli.NewCommand[mergeOptions]("merge", "Merge verified audit journals chronologically as JSON Lines.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleMerge),
	}
}

func handleManagementMerge(ctx context.Context, opts managementMergeOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Audit == nil {
		return fmt.Errorf("management audit repository is unavailable")
	}
	names, err := parseAuditlogNames(opts.Auditlogs)
	if err != nil {
		return err
	}
	return access.Audit.Export(ctx, names, opts.WithSensitive,
		audit.RecordOrderChronological, cli.StdoutOfContext(ctx))
}

func handleMerge(ctx context.Context, opts mergeOptions) error {
	names, err := parseAuditlogNames(opts.Auditlogs)
	if err != nil {
		return err
	}
	conf, err := common.ResolveConfiguration(ctx, opts)
	if err != nil {
		return err
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
		return EnsureAuditDestinationSafe(ctx, output, stdout, conf.Filename, conf, opts.DecryptionIdentityFiles)
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

func remoteHandleMerge(ctx context.Context, opts mergeOptions) error {
	if opts.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	names, err := parseAuditlogNames(opts.Auditlogs)
	if err != nil {
		return err
	}
	return runRemoteAudit(ctx, target, remoteAuditOptions{
		Operation: remoteMerge, Names: names, TrustAnchors: opts.ExpectedProducerIds,
		IdentityFiles: opts.DecryptionIdentityFiles,
		Output:        opts.Output, Force: opts.Force, WithSensitive: opts.WithSensitive,
		Format: format.Text,
	}, cli.StdoutOfContext(ctx))
}

func parseAuditlogNames(values []string) ([]configuration.AuditlogName, error) {
	names := make([]configuration.AuditlogName, 0, len(values))
	for _, value := range values {
		name := configuration.AuditlogName(value)
		if err := name.Validate(); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}
