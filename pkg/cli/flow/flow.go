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

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[flowOptions]("flow", "Inspect configured flows.").
			WithProfiles(common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement).
			WithCommand(
				cli.NewCommand[listOptions]("ls", "List configured flows.").
					WithProfiles(common.ProfileExecutable).
					WithHandler(handleList),
				cli.NewCommand[listOptions]("ls", "List configured flows.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleList),
				cli.NewCommand[listOptions]("ls", "List configured flows.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementList),
			).
			WithCommand(
				cli.NewCommand[showOptions]("show", "Show the settings of one flow.").
					WithProfiles(common.ProfileExecutable).
					WithHandler(handleShow),
				cli.NewCommand[showOptions]("show", "Show the settings of one flow.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleShow),
				cli.NewCommand[showOptions]("show", "Show the settings of one flow.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementShow),
			),
	}
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
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
		return err
	}
	return ListFlows(cli.StdoutOfContext(ctx), opts.Parent.Format, conf)
}

func remoteHandleList(ctx context.Context, opts listOptions) error {
	if opts.Parent.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "flow", "ls", "--format="+string(opts.Parent.Format))
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
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
		return err
	}
	return ShowFlow(cli.StdoutOfContext(ctx), opts.Parent.Format, conf, opts.Name, false)
}

func remoteHandleShow(ctx context.Context, opts showOptions) error {
	if opts.Parent.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "flow", "show", opts.Name.String(), "--format="+string(opts.Parent.Format))
}
