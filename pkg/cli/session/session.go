package session

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfSession "github.com/engity-com/bifroest/pkg/session"
)

type sessionOptions struct {
	format.Opts
	common.ExecutableConfigurationOpts
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

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[sessionOptions]("session", "Inspect Bifröst sessions.").
			WithProfiles(common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement).
			WithCommand(
				cli.NewCommand[listOptions]("ls", "List active sessions by default.").
					WithProfiles(common.ProfileExecutable).
					WithHandler(handleList),
				cli.NewCommand[listOptions]("ls", "List active sessions by default.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleList),
				cli.NewCommand[listOptions]("ls", "List active sessions by default.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementList),
			).
			WithCommand(
				cli.NewCommand[showOptions]("show", "Show one session by ID.").
					WithProfiles(common.ProfileExecutable).
					WithHandler(handleShow),
				cli.NewCommand[showOptions]("show", "Show one session by ID.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleShow),
				cli.NewCommand[showOptions]("show", "Show one session by ID.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementShow),
			),
	}
}

func handleManagementList(ctx context.Context, opts listOptions) error {
	source, err := managementSessionSource(ctx)
	if err != nil {
		return err
	}
	return listSessions(ctx, opts.Parent.Format, opts.listFilterOptions, source)
}

func handleManagementShow(ctx context.Context, opts showOptions) error {
	source, err := managementSessionSource(ctx)
	if err != nil {
		return err
	}
	return showSession(ctx, opts.Parent.Format, opts.ID, source)
}

func managementSessionSource(ctx context.Context) (SessionSource, error) {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Sessions == nil {
		return nil, fmt.Errorf("management session repository is unavailable")
	}
	return SessionSourceFromRepository(access.Sessions), nil
}

func localSessionSource(conf *configuration.Configuration) SessionSource {
	return func(ctx context.Context, consumer func(context.Context, bfSession.Info) (bool, error), diagnostics bfSession.FindDiagnosticConsumer) error {
		fs, ok := conf.Session.V.(*configuration.SessionFs)
		if !ok {
			return fmt.Errorf("local inspection does not support session repository %T", conf.Session.V)
		}
		return bfSession.InspectFsSessions(ctx, fs, consumer, diagnostics)
	}
}

func handleList(ctx context.Context, opts listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	return listSessions(ctx, opts.Parent.Format, opts.listFilterOptions, localSessionSource(conf))
}

func remoteHandleList(ctx context.Context, opts listOptions) error {
	if opts.Parent.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	args := []string{"session", "ls", "--state=" + opts.State, "--format=" + string(opts.Parent.Format)}
	if opts.Flow != "" {
		args = append(args, "--flow="+opts.Flow)
	}
	if opts.User != "" {
		args = append(args, "--user="+opts.User)
	}
	return target.Run(ctx, args...)
}

func listSessions(ctx context.Context, selected format.Format, filters listFilterOptions, source SessionSource) error {
	return ListSessions(ctx, cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), source,
		filters.Flow, filters.User, filters.State, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
			return cli.ErrPrintln(ctx, diagnostic.Error())
		})
}

func handleShow(ctx context.Context, opts showOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts.Parent)
	if err != nil {
		return err
	}
	return showSession(ctx, opts.Parent.Format, opts.ID, localSessionSource(conf))
}

func remoteHandleShow(ctx context.Context, opts showOptions) error {
	if opts.Parent.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "session", "show", opts.ID.String(), "--format="+string(opts.Parent.Format))
}

func showSession(ctx context.Context, selected format.Format, id bfSession.Id, source SessionSource) error {
	return ShowSession(ctx, cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, selected), source,
		id, func(_ context.Context, diagnostic bfSession.FindDiagnostic) error {
			return cli.ErrPrintln(ctx, diagnostic.Error())
		})
}
