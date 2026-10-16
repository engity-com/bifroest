package audit

import (
	"context"
	"fmt"
	"time"

	cli "github.com/echocat/cli4g"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type listOptions struct {
	common.ExecutableConfigurationOpts
	format.Opts
}

type showOptions struct {
	listOptions
	ConfiguredAuditlogOptions
}

type eventFilterOptions struct {
	EventName string    `flag:"name" description:"Filter by event name."`
	FlowName  string    `flag:"flow" description:"Filter by flow; requires --with-sensitive."`
	Since     time.Time `flag:"since" type:"rfc3339" description:"RFC3339 start time."`
	Until     time.Time `flag:"until" type:"rfc3339" description:"RFC3339 end time."`
	Limit     uint      `flag:"limit" default:"100" description:"Number of newest matching events; zero means all."`
}

type eventsOptions struct {
	showOptions
	eventFilterOptions
	common.WithSensitiveOpts
	DecryptionIdentityFiles []string `flag:"decryptionIdentityFile" profile:"executable|remote" description:"Local private key for encrypted content; repeatable."`
	ExpectedProducerID      string   `flag:"expectedProducerId" profile:"remote" description:"Independently trusted producer ID for remote sensitive events."`
}

func createBrowseCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[listOptions]("ls", "List configured audit logs.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleList),
		cli.NewCommand[listOptions]("ls", "List configured audit logs.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleList),
		cli.NewCommand[listOptions]("ls", "List configured audit logs.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementList),

		cli.NewCommand[showOptions]("show", "Show audit-log settings.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleShow),
		cli.NewCommand[showOptions]("show", "Show audit-log settings.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleShow),
		cli.NewCommand[showOptions]("show", "Show audit-log settings.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementShow),

		cli.NewCommand[eventsOptions]("events", "Show verified audit events.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleEvents),
		cli.NewCommand[eventsOptions]("events", "Show verified audit events.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleEvents),
		cli.NewCommand[eventsOptions]("events", "Show verified audit events.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementEvents),
	}
}

func handleManagementList(ctx context.Context, options listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	return ListAuditlogs(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, options.Format), conf)
}

func handleList(ctx context.Context, options listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	return ListAuditlogs(cli.StdoutOfContext(ctx), options.Format, conf)
}

func remoteHandleList(ctx context.Context, options listOptions) error {
	if options.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "audit", "ls", "--format="+string(options.Format))
}

func handleManagementShow(ctx context.Context, options showOptions) error {
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	return ShowAuditlog(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, options.Format), conf, options.Name)
}

func handleShow(ctx context.Context, options showOptions) error {
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	return ShowAuditlog(cli.StdoutOfContext(ctx), options.Format, conf, options.Name)
}

func remoteHandleShow(ctx context.Context, options showOptions) error {
	if options.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "audit", "show", options.Name.String(), "--format="+string(options.Format))
}

func handleManagementEvents(ctx context.Context, options eventsOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.ProducerID == nil {
		return fmt.Errorf("management audit identity is unavailable")
	}
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	if options.WithSensitive && !access.AllowArtifactTransfer {
		return fmt.Errorf("sensitive audit events require allowArtifactTransfer in the management environment")
	}
	expected, err := access.ProducerID(options.Name)
	if err != nil {
		return err
	}
	return writeEvents(ctx, conf, options.Name, expected, options.Format, options.eventFilterOptions, options.WithSensitive, nil)
}

func handleEvents(ctx context.Context, options eventsOptions) error {
	if options.ExpectedProducerID != "" {
		return fmt.Errorf("--expectedProducerId for audit events requires a remote target and --with-sensitive")
	}
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return err
	}
	configured, err := FindConfigured(conf, options.Name)
	if err != nil {
		return err
	}
	key, err := LoadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return err
	}
	identity, err := bfAudit.NewIdentity(key)
	if err != nil {
		return err
	}
	return writeEvents(ctx, conf, options.Name, identity.ProducerId(), options.Format, options.eventFilterOptions, options.WithSensitive, options.DecryptionIdentityFiles)
}

func remoteHandleEvents(ctx context.Context, options eventsOptions) error {
	if options.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	if options.WithSensitive {
		return doRemoteAuditEvents(ctx, target, AuditEventsOptions{
			Format: options.Format, Auditlog: options.Name,
			EventName: options.EventName, FlowName: options.FlowName,
			Since: options.Since, Until: options.Until, Limit: options.Limit,
			WithSensitive: true, IdentityFiles: options.DecryptionIdentityFiles,
			ExpectedProducerID: options.ExpectedProducerID,
		}, cli.StdoutOfContext(ctx))
	}
	if options.ExpectedProducerID != "" || len(options.DecryptionIdentityFiles) != 0 {
		return fmt.Errorf("sensitive audit options require --with-sensitive")
	}
	args := []string{"audit", "events", options.Name.String(), "--format=" + string(options.Format), fmt.Sprintf("--limit=%d", options.Limit)}
	if options.EventName != "" {
		args = append(args, "--name="+options.EventName)
	}
	if options.FlowName != "" {
		args = append(args, "--flow="+options.FlowName)
	}
	if !options.Since.IsZero() {
		args = append(args, "--since="+options.Since.Format(time.RFC3339))
	}
	if !options.Until.IsZero() {
		args = append(args, "--until="+options.Until.Format(time.RFC3339))
	}
	return target.Run(ctx, args...)
}

func writeEvents(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName, expected bfAudit.ProducerId, selected format.Format, options eventFilterOptions, sensitive bool, identities []string) error {
	filter := EventFilter{
		Name: options.EventName, Flow: options.FlowName,
		Since: options.Since, Until: options.Until, Limit: options.Limit,
	}
	records, err := ReadAuditEvents(ctx, conf, name, expected, sensitive, identities)
	if err != nil {
		return err
	}
	records, err = FilterEvents(records, filter, sensitive)
	if err != nil {
		return err
	}
	return format.WriteAuditEvents(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), records, sensitive)
}
