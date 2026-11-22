package metrics

import (
	"context"
	"fmt"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	managementaccess "github.com/engity-com/bifroest/pkg/management/access"
)

type showOptions struct {
	format.MetricsOpts
	Names []string `argument:"metric" description:"Exact metric family names; omit to show all available metrics."`
}

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("metrics", "Inspect live operational metrics.").
			WithProfiles(common.ProfileRemote, common.ProfileManagement).
			WithCommand(
				cli.NewCommand[showOptions]("show", "Show a snapshot of all or selected metric families.").
					WithProfiles(common.ProfileManagement).WithHandler(handleShow),
				cli.NewCommand[showOptions]("show", "Show a snapshot of all or selected metric families.").
					WithProfiles(common.ProfileRemote).WithHandler(remoteHandleShow),
			),
	}
}

func handleShow(ctx context.Context, opts showOptions) error {
	if err := common.RequireManagementPermission(ctx, managementaccess.MetricsRead); err != nil {
		return err
	}
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Metrics == nil {
		return fmt.Errorf("management metrics are unavailable")
	}
	snapshot, err := access.Metrics.Snapshot(ctx, opts.Names)
	if err != nil {
		return err
	}
	return format.WriteMetrics(cli.StdoutOfContext(ctx), common.MetricsFormatForInvocation(ctx, opts.Format), snapshot)
}

func remoteHandleShow(ctx context.Context, opts showOptions) error {
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	snapshot, err := target.Metrics(ctx, opts.Names)
	if err != nil {
		return err
	}
	return format.WriteMetrics(cli.StdoutOfContext(ctx), opts.Format, snapshot)
}
