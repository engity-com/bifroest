package flow

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/managementclient"
)

type flowOptions struct {
	configuration.EmptyStrOpts
	format.Opts
}

type flowNameOptions struct {
	Name configuration.FlowName `argument:"name" required:"true" description:"Name of the flow."`
}

type listOptions struct {
	Parent *flowOptions `parent:"matchingType"`
}

type showOptions struct {
	Parent *flowOptions `parent:"matchingType"`
	flowNameOptions
}

type managementFlowOptions struct{ format.Opts }

type managementListOptions struct {
	Parent *managementFlowOptions `parent:"matchingType"`
}

type managementShowOptions struct {
	Parent *managementFlowOptions `parent:"matchingType"`
	flowNameOptions
}

func Register(_ context.Context, parent cli.ContainerRequirementSetters, usage common.Usage) {
	if usage == common.UsageManagement {
		command := cli.NewCommand[managementFlowOptions]().
			WithName("flow").
			WithDescription("Inspect configured flows.")
		command.AddCommand(
			cli.NewCommand[managementListOptions]().
				WithName("ls").
				WithDescription("List configured flows.").
				WithHandler(handleManagementList),
		)
		command.AddCommand(
			cli.NewCommand[managementShowOptions]().
				WithName("show").
				WithDescription("Show the settings of one flow.").
				WithHandler(handleManagementShow),
		)
		parent.AddCommand(command)
		return
	}
	command := cli.NewCommand[flowOptions]().
		WithName("flow").
		WithDescription("Inspect configured flows.")
	command.AddCommand(
		cli.NewCommand[listOptions]().
			WithName("ls").
			WithDescription("List configured flows.").
			WithHandler(handleList),
	)
	command.AddCommand(
		cli.NewCommand[showOptions]().
			WithName("show").
			WithDescription("Show the settings of one flow.").
			WithHandler(handleShow),
	)
	parent.AddCommand(command)
}

func handleManagementList(ctx context.Context, opts managementListOptions) error {
	conf, err := managementConfiguration(ctx)
	if err != nil {
		return err
	}
	return ListFlows(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Parent.Format), conf)
}

func handleManagementShow(ctx context.Context, opts managementShowOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Configuration == nil {
		return fmt.Errorf("management configuration is unavailable")
	}
	return ShowFlow(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Parent.Format), access.Configuration, opts.Name, access.IncludingCredentials)
}

func handleList(ctx context.Context, opts listOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if opts.Parent.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{"flow", "ls", "--format=" + string(opts.Parent.Format)}, cli.StdoutOfContext(ctx))
	}
	conf, err := common.LoadManagementConfiguration(opts.Parent.Configuration)
	if err != nil {
		return err
	}
	return ListFlows(cli.StdoutOfContext(ctx), opts.Parent.Format, conf)
}

func handleShow(ctx context.Context, opts showOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if opts.Parent.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{"flow", "show", opts.Name.String(), "--format=" + string(opts.Parent.Format)}, cli.StdoutOfContext(ctx))
	}
	conf, err := common.LoadManagementConfiguration(opts.Parent.Configuration)
	if err != nil {
		return err
	}
	return ShowFlow(cli.StdoutOfContext(ctx), opts.Parent.Format, conf, opts.Name, false)
}

func managementConfiguration(ctx context.Context) (*configuration.Configuration, error) {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Configuration == nil {
		return nil, fmt.Errorf("management configuration is unavailable")
	}
	return access.Configuration, nil
}
