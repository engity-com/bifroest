package version

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/managementclient"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Long bool `flag:"long" description:"Include build, platform and feature details."`
}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage common.Usage, version sys.Version) {
	c.AddCommand(cli.NewCommand[opts]().
		WithName("version").
		WithDescription((func() string {
			switch usage {
			case common.UsageExecutable:
				return "Show version details of this executable."
			default:
				return "Show version details of this Bifröst instance."
			}
		})()).
		WithHandler(func(ctx context.Context, o opts) error {
			return handle(ctx, o, version)
		}),
	)
}

func handle(ctx context.Context, o opts, version sys.Version) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		command := "version"
		if o.Long {
			command += " --long"
		}
		return managementclient.RunDirect(ctx, target, command, cli.StdoutOfContext(ctx))
	}
	f := sys.VersionFormatShort
	if o.Long {
		f = sys.VersionFormatLong
	}
	return cli.Println(ctx, sys.FormatVersion(version, f))
}
