package flow

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
)

type listOptions struct {
	configuration.EmptyStrOpts
	format.Opts
}

type showOptions struct {
	listOptions
	Name configuration.FlowName `argument:"name" required:"true" description:"Name of the flow."`
}

type managementListOptions struct{ format.Opts }

type managementShowOptions struct {
	managementListOptions
	Name configuration.FlowName `argument:"name" required:"true" description:"Name of the flow."`
}

func Register(_ context.Context, parent cli.ContainerRequirementSetters, usage common.Usage) {
	command := cli.NewSimpleCommand().WithName("flow").WithDescription("Inspect configured flows.")
	if usage == common.UsageManagement {
		command.AddCommand(cli.NewCommand[managementListOptions]().WithName("ls").WithHandler(func(ctx context.Context, opts managementListOptions) error {
			conf, err := managementConfiguration(ctx)
			if err != nil {
				return err
			}
			return management.ListFlows(cli.StdoutOfContext(ctx), outputFormat(opts.Format), conf)
		}))
		command.AddCommand(cli.NewCommand[managementShowOptions]().WithName("show").WithHandler(func(ctx context.Context, opts managementShowOptions) error {
			access, ok := common.ManagementAccessFromContext(ctx)
			if !ok || access.Configuration == nil {
				return fmt.Errorf("management configuration is unavailable")
			}
			return management.ShowFlow(cli.StdoutOfContext(ctx), outputFormat(opts.Format), access.Configuration, opts.Name, access.IncludingCredentials)
		}))
	} else {
		command.AddCommand(cli.NewCommand[listOptions]().WithName("ls").WithHandler(func(ctx context.Context, opts listOptions) error {
			conf, err := common.LoadManagementConfiguration(opts.Configuration)
			if err != nil {
				return err
			}
			return management.ListFlows(cli.StdoutOfContext(ctx), outputFormat(opts.Format), conf)
		}))
		command.AddCommand(cli.NewCommand[showOptions]().WithName("show").WithHandler(func(ctx context.Context, opts showOptions) error {
			conf, err := common.LoadManagementConfiguration(opts.Configuration)
			if err != nil {
				return err
			}
			return management.ShowFlow(cli.StdoutOfContext(ctx), outputFormat(opts.Format), conf, opts.Name, false)
		}))
	}
	parent.AddCommand(command)
}

func managementConfiguration(ctx context.Context) (*configuration.Configuration, error) {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Configuration == nil {
		return nil, fmt.Errorf("management configuration is unavailable")
	}
	return access.Configuration, nil
}

func outputFormat(value format.Format) management.Format {
	switch value {
	case format.Json:
		return management.FormatJSON
	case format.Yaml:
		return management.FormatYAML
	default:
		return management.FormatTable
	}
}
