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
		cli.NewCommand[sessionOptions]("session", "Inspect and manage Bifröst sessions.").
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
			).
			WithCommand(
				cli.NewCommand[showOptions]("disconnect", "Disconnect a session's current SSH connections without revoking it.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleDisconnect),
				cli.NewCommand[showOptions]("disconnect", "Disconnect a session's current SSH connections without revoking it.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementDisconnect),
			).
			WithCommand(
				cli.NewCommand[showOptions]("dispose", "Revoke a session, disconnect it and clean up its environment and authorization.").
					WithProfiles(common.ProfileRemote).
					WithHandler(remoteHandleDispose),
				cli.NewCommand[showOptions]("dispose", "Revoke a session, disconnect it and clean up its environment and authorization.").
					WithProfiles(common.ProfileManagement).
					WithHandler(handleManagementDispose),
			),
	}
}

func handleManagementDisconnect(ctx context.Context, opts showOptions) error {
	return handleManagementAction(ctx, opts, false)
}

func handleManagementDispose(ctx context.Context, opts showOptions) error {
	return handleManagementAction(ctx, opts, true)
}

func handleManagementAction(ctx context.Context, opts showOptions, dispose bool) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.SessionControl == nil {
		return fmt.Errorf("management session control is unavailable")
	}
	action := access.SessionControl.Disconnect
	if dispose {
		action = access.SessionControl.Dispose
	}
	result, err := action(ctx, opts.ID)
	if err != nil {
		return err
	}
	return format.WriteSessionAction(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Parent.Format), result)
}

func remoteHandleDisconnect(ctx context.Context, opts showOptions) error {
	return remoteHandleAction(ctx, opts, "disconnect")
}

func remoteHandleDispose(ctx context.Context, opts showOptions) error {
	return remoteHandleAction(ctx, opts, "dispose")
}

func remoteHandleAction(ctx context.Context, opts showOptions, action string) error {
	if opts.Parent.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "session", action, opts.ID.String(), "--format="+string(opts.Parent.Format))
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
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
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
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
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
