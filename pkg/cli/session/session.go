package session

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	bfSession "github.com/engity-com/bifroest/pkg/session"
)

type listOptions struct {
	configuration.EmptyStrOpts
	format.Opts
	Flow  string `flag:"flow" description:"Filter by flow name."`
	User  string `flag:"user" description:"Filter by requesting user."`
	State string `flag:"state" default:"active" enums:"active|new|authorized|disposed|all" description:"Session state to select."`
}

type showOptions struct {
	configuration.EmptyStrOpts
	format.Opts
	ID bfSession.Id `argument:"id" required:"true" description:"Session UUID."`
}

type managementListOptions struct {
	format.Opts
	Flow  string `flag:"flow" description:"Filter by flow name."`
	User  string `flag:"user" description:"Filter by requesting user."`
	State string `flag:"state" default:"active" enums:"active|new|authorized|disposed|all" description:"Session state to select."`
}

type managementShowOptions struct {
	format.Opts
	ID bfSession.Id `argument:"id" required:"true" description:"Session UUID."`
}

func Register(_ context.Context, parent cli.ContainerRequirementSetters, usage common.Usage) {
	command := cli.NewSimpleCommand().WithName("session").WithDescription("Inspect Bifröst sessions.")
	if usage == common.UsageManagement {
		command.AddCommand(cli.NewCommand[managementListOptions]().WithName("ls").WithHandler(func(ctx context.Context, opts managementListOptions) error {
			return list(ctx, "", opts.Format, opts.Flow, opts.User, opts.State, true)
		}))
		command.AddCommand(cli.NewCommand[managementShowOptions]().WithName("show").WithHandler(func(ctx context.Context, opts managementShowOptions) error {
			return show(ctx, "", opts.Format, opts.ID, true)
		}))
	} else {
		command.AddCommand(cli.NewCommand[listOptions]().WithName("ls").WithHandler(func(ctx context.Context, opts listOptions) error {
			return list(ctx, opts.Configuration, opts.Format, opts.Flow, opts.User, opts.State, false)
		}))
		command.AddCommand(cli.NewCommand[showOptions]().WithName("show").WithHandler(func(ctx context.Context, opts showOptions) error {
			return show(ctx, opts.Configuration, opts.Format, opts.ID, false)
		}))
	}
	parent.AddCommand(command)
}

func sessionSource(ctx context.Context, managementInvocation bool) (management.SessionSource, error) {
	if managementInvocation {
		access, ok := common.ManagementAccessFromContext(ctx)
		if !ok || access.Sessions == nil {
			return nil, fmt.Errorf("management session repository is unavailable")
		}
		return management.SessionSourceFromRepository(access.Sessions), nil
	}
	return func(ctx context.Context, path string, consumer func(context.Context, bfSession.Info) (bool, error), diagnostics bfSession.FindDiagnosticConsumer) error {
		conf, err := common.LoadManagementConfiguration(path)
		if err != nil {
			return err
		}
		fs, ok := conf.Session.V.(*configuration.SessionFs)
		if !ok {
			return fmt.Errorf("local inspection does not support session repository %T", conf.Session.V)
		}
		return bfSession.InspectFsSessions(ctx, fs, consumer, diagnostics)
	}, nil
}

func list(ctx context.Context, configurationPath string, selected format.Format, flow, user, state string, remote bool) error {
	source, err := sessionSource(ctx, remote)
	if err != nil {
		return err
	}
	return management.ListSessions(ctx, cli.StdoutOfContext(ctx), outputFormat(selected), source, configurationPath, flow, user, state, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
		return cli.ErrPrintln(ctx, diagnostic.Error())
	})
}

func show(ctx context.Context, configurationPath string, selected format.Format, id bfSession.Id, remote bool) error {
	source, err := sessionSource(ctx, remote)
	if err != nil {
		return err
	}
	return management.ShowSession(ctx, cli.StdoutOfContext(ctx), outputFormat(selected), source, configurationPath, id, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
		return cli.ErrPrintln(ctx, diagnostic.Error())
	})
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
