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
	"github.com/engity-com/bifroest/pkg/managementclient"
)

type listOptions struct {
	configuration.EmptyStrOpts
	format.Opts
}

type nameOptions struct {
	Name configuration.AuditlogName `argument:"name" required:"true" description:"Auditlog name."`
}

type showOptions struct {
	listOptions
	nameOptions
}

type eventFilterOptions struct {
	EventName string    `flag:"name" description:"Filter by event name."`
	FlowName  string    `flag:"flow" description:"Filter by flow; requires --with-sensitive."`
	Since     time.Time `flag:"since" type:"rfc3339" description:"RFC3339 start time."`
	Until     time.Time `flag:"until" type:"rfc3339" description:"RFC3339 end time."`
	Limit     int       `flag:"limit" default:"100" description:"Number of newest matching events; zero means all."`
}

type eventsOptions struct {
	showOptions
	eventFilterOptions
	common.WithSensitiveOpts
	common.DecryptionIdentityFilesOpts
	ExpectedProducerID string `flag:"expectedProducerId" description:"Independently trusted producer ID for remote sensitive events."`
}

type managementListOptions struct{ format.Opts }

type managementShowOptions struct {
	managementListOptions
	nameOptions
}

type managementEventsOptions struct {
	managementShowOptions
	eventFilterOptions
	common.WithSensitiveOpts
}

func registerBrowse(parent cli.ContainerRequirementSetters, usage common.Usage) {
	if usage == common.UsageManagement {
		parent.AddCommand(
			cli.NewCommand[managementListOptions]().
				WithName("ls").
				WithDescription("List configured audit logs.").
				WithHandler(handleManagementList),
		)
		parent.AddCommand(
			cli.NewCommand[managementShowOptions]().
				WithName("show").
				WithDescription("Show audit-log settings.").
				WithHandler(handleManagementShow),
		)
		parent.AddCommand(
			cli.NewCommand[managementEventsOptions]().
				WithName("events").
				WithDescription("Show verified audit events.").
				WithHandler(handleManagementEvents),
		)
		return
	}
	parent.AddCommand(
		cli.NewCommand[listOptions]().
			WithName("ls").
			WithDescription("List configured audit logs.").
			WithHandler(handleList),
	)
	parent.AddCommand(
		cli.NewCommand[showOptions]().
			WithName("show").
			WithDescription("Show audit-log settings.").
			WithHandler(handleShow),
	)
	parent.AddCommand(
		cli.NewCommand[eventsOptions]().
			WithName("events").
			WithDescription("Show verified audit events.").
			WithHandler(handleEvents),
	)
}

func managementConfiguration(ctx context.Context) (*configuration.Configuration, error) {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Configuration == nil {
		return nil, fmt.Errorf("management configuration is unavailable")
	}
	return access.Configuration, nil
}

func handleManagementList(ctx context.Context, options managementListOptions) error {
	conf, err := managementConfiguration(ctx)
	if err != nil {
		return err
	}
	return ListAuditlogs(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, options.Format), conf)
}

func handleManagementShow(ctx context.Context, options managementShowOptions) error {
	conf, err := managementConfiguration(ctx)
	if err != nil {
		return err
	}
	return ShowAuditlog(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, options.Format), conf, options.Name)
}

func handleManagementEvents(ctx context.Context, options managementEventsOptions) error {
	return showEvents(ctx, options.Name, options.Format, options.eventFilterOptions, options.WithSensitive, nil, true, "")
}

func handleList(ctx context.Context, options listOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if options.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{
			"audit", "ls", "--format=" + string(options.Format),
		}, cli.StdoutOfContext(ctx))
	}
	conf, err := common.LoadManagementConfiguration(options.Configuration)
	if err != nil {
		return err
	}
	return ListAuditlogs(cli.StdoutOfContext(ctx), options.Format, conf)
}

func handleShow(ctx context.Context, options showOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if options.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{
			"audit", "show", options.Name.String(), "--format=" + string(options.Format),
		}, cli.StdoutOfContext(ctx))
	}
	conf, err := common.LoadManagementConfiguration(options.Configuration)
	if err != nil {
		return err
	}
	return ShowAuditlog(cli.StdoutOfContext(ctx), options.Format, conf, options.Name)
}

func handleEvents(ctx context.Context, options eventsOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if options.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		if options.WithSensitive {
			var since, until string
			if !options.Since.IsZero() {
				since = options.Since.Format(time.RFC3339)
			}
			if !options.Until.IsZero() {
				until = options.Until.Format(time.RFC3339)
			}
			return doRemoteAuditEvents(ctx, target, AuditEventsOptions{
				Format: options.Format, Auditlog: options.Name,
				EventName: options.EventName, FlowName: options.FlowName,
				Since: since, Until: until, Limit: options.Limit,
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
		return managementclient.Run(ctx, target, args, cli.StdoutOfContext(ctx))
	}
	if options.ExpectedProducerID != "" {
		return fmt.Errorf("--expectedProducerId for audit events requires a remote target and --with-sensitive")
	}
	return showEvents(ctx, options.Name, options.Format, options.eventFilterOptions, options.WithSensitive, options.DecryptionIdentityFiles, false, options.Configuration)
}

func showEvents(ctx context.Context, name configuration.AuditlogName, selected format.Format, options eventFilterOptions, sensitive bool, identities []string, remote bool, path string) error {
	var conf *configuration.Configuration
	var expected bfAudit.ProducerId
	var err error
	if remote {
		access, ok := common.ManagementAccessFromContext(ctx)
		if !ok || access.ProducerID == nil {
			return fmt.Errorf("management audit identity is unavailable")
		}
		if sensitive && !access.AllowArtifactTransfer {
			return fmt.Errorf("sensitive audit events require allowArtifactTransfer in the management environment")
		}
		conf = access.Configuration
		expected, err = access.ProducerID(name)
	} else {
		conf, err = common.LoadManagementConfiguration(path)
		if err != nil {
			return err
		}
		configured, findErr := FindConfigured(conf, name)
		if findErr != nil {
			return findErr
		}
		key, loadErr := LoadAuditPrivateKey(configured.IdentityFile)
		if loadErr != nil {
			return loadErr
		}
		identity, identityErr := bfAudit.NewIdentity(key)
		if identityErr != nil {
			return identityErr
		}
		expected = identity.ProducerId()
	}
	if err != nil {
		return err
	}
	filter := format.AuditEventFilter{
		Name: options.EventName, Flow: options.FlowName,
		Since: options.Since, Until: options.Until, Limit: options.Limit,
	}
	records, err := ReadAuditEvents(ctx, conf, name, expected, sensitive, identities)
	if err != nil {
		return err
	}
	return format.WriteAuditEvents(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), records, filter, sensitive)
}
