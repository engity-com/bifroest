package flow

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
)

type flowOptions struct {
	format.Opts
	common.ExecutableConfigurationOpts
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

func Register(parent cli.ContainerRequirementSetters) {
	command := cli.NewCommand[flowOptions]("flow", "Inspect configured flows.").
		WithProfiles(common.ProfileExecutable, common.ProfileManagement)
	command.AddCommand(
		cli.NewCommand[listOptions]("ls", "List configured flows.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleList),
		cli.NewCommand[listOptions]("ls", "List configured flows.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementList),
	)
	command.AddCommand(
		cli.NewCommand[showOptions]("show", "Show the settings of one flow.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleShow),
		cli.NewCommand[showOptions]("show", "Show the settings of one flow.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementShow),
	)
	parent.AddCommand(command)
}

func handleManagementList(ctx context.Context, opts listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	return ListFlows(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Parent.Format), conf)
}

func handleList(ctx context.Context, opts listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if conf != nil {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return target.Run(ctx, "flow", "ls", "--format="+string(opts.Parent.Format))
	}
	return ListFlows(cli.StdoutOfContext(ctx), opts.Parent.Format, conf)
}

func handleManagementShow(ctx context.Context, opts showOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok {
		return fmt.Errorf("management configuration is unavailable")
	}
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	return ShowFlow(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Parent.Format), conf, opts.Name, access.IncludingCredentials)
}

func handleShow(ctx context.Context, opts showOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if conf != nil {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return target.Run(ctx, "flow", "show", opts.Name.String(), "--format="+string(opts.Parent.Format))
	}
	return ShowFlow(cli.StdoutOfContext(ctx), opts.Parent.Format, conf, opts.Name, false)
}
