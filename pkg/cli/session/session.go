package session

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/managementclient"
	bfSession "github.com/engity-com/bifroest/pkg/session"
)

type sessionOptions struct {
	configuration.EmptyStrOpts
	format.Opts
}

type listFilterOptions struct {
	Flow  string `flag:"flow" description:"Filter by flow name."`
	User  string `flag:"user" description:"Filter by requesting user."`
	State string `flag:"state" default:"active" enum:"active|new|authorized|disposed|all" description:"Session state to select."`
}

type sessionIDOptions struct {
	ID bfSession.Id `argument:"id" required:"true" description:"Session UUID."`
}

type listOptions struct {
	Parent *sessionOptions `parent:"matchingType"`
	listFilterOptions
}

type showOptions struct {
	Parent *sessionOptions `parent:"matchingType"`
	sessionIDOptions
}

type managementSessionOptions struct{ format.Opts }

type managementListOptions struct {
	Parent *managementSessionOptions `parent:"matchingType"`
	listFilterOptions
}

type managementShowOptions struct {
	Parent *managementSessionOptions `parent:"matchingType"`
	sessionIDOptions
}

func Register(_ context.Context, parent cli.ContainerRequirementSetters, usage common.Usage) {
	if usage == common.UsageManagement {
		command := cli.NewCommand[managementSessionOptions]().
			WithName("session").
			WithDescription("Inspect Bifröst sessions.")
		command.AddCommand(
			cli.NewCommand[managementListOptions]().
				WithName("ls").
				WithDescription("List active sessions by default.").
				WithHandler(handleManagementList),
		)
		command.AddCommand(
			cli.NewCommand[managementShowOptions]().
				WithName("show").
				WithDescription("Show one session by ID.").
				WithHandler(handleManagementShow),
		)
		parent.AddCommand(command)
		return
	}
	command := cli.NewCommand[sessionOptions]().
		WithName("session").
		WithDescription("Inspect Bifröst sessions.")
	command.AddCommand(
		cli.NewCommand[listOptions]().
			WithName("ls").
			WithDescription("List active sessions by default.").
			WithHandler(handleList),
	)
	command.AddCommand(
		cli.NewCommand[showOptions]().
			WithName("show").
			WithDescription("Show one session by ID.").
			WithHandler(handleShow),
	)
	parent.AddCommand(command)
}

func handleManagementList(ctx context.Context, opts managementListOptions) error {
	return list(ctx, "", opts.Parent.Format, opts.listFilterOptions, true)
}

func handleManagementShow(ctx context.Context, opts managementShowOptions) error {
	return show(ctx, "", opts.Parent.Format, opts.ID, true)
}

func handleList(ctx context.Context, opts listOptions) error {
	return list(ctx, opts.Parent.Configuration, opts.Parent.Format, opts.listFilterOptions, false)
}

func handleShow(ctx context.Context, opts showOptions) error {
	return show(ctx, opts.Parent.Configuration, opts.Parent.Format, opts.ID, false)
}

func sessionSource(ctx context.Context, managementInvocation bool) (SessionSource, error) {
	if managementInvocation {
		access, ok := common.ManagementAccessFromContext(ctx)
		if !ok || access.Sessions == nil {
			return nil, fmt.Errorf("management session repository is unavailable")
		}
		return SessionSourceFromRepository(access.Sessions), nil
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

func list(ctx context.Context, configurationPath string, selected format.Format, filters listFilterOptions, remote bool) error {
	if !remote {
		if target, exists := common.RemoteTargetFromContext(ctx); exists {
			if configurationPath != "" {
				return fmt.Errorf("--configuration cannot be combined with a remote target")
			}
			args := []string{"session", "ls", "--state=" + filters.State, "--format=" + string(selected)}
			if filters.Flow != "" {
				args = append(args, "--flow="+filters.Flow)
			}
			if filters.User != "" {
				args = append(args, "--user="+filters.User)
			}
			return managementclient.Run(ctx, target, args, cli.StdoutOfContext(ctx))
		}
	}
	source, err := sessionSource(ctx, remote)
	if err != nil {
		return err
	}
	return ListSessions(ctx, cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), source,
		configurationPath, filters.Flow, filters.User, filters.State, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
			return cli.ErrPrintln(ctx, diagnostic.Error())
		})
}

func show(ctx context.Context, configurationPath string, selected format.Format, id bfSession.Id, remote bool) error {
	if !remote {
		if target, exists := common.RemoteTargetFromContext(ctx); exists {
			if configurationPath != "" {
				return fmt.Errorf("--configuration cannot be combined with a remote target")
			}
			return managementclient.Run(ctx, target, []string{"session", "show", id.String(), "--format=" + string(selected)}, cli.StdoutOfContext(ctx))
		}
	}
	source, err := sessionSource(ctx, remote)
	if err != nil {
		return err
	}
	return ShowSession(ctx, cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), source,
		configurationPath, id, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
			return cli.ErrPrintln(ctx, diagnostic.Error())
		})
}
