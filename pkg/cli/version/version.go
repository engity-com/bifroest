package version

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Long bool `flag:"long" description:"Include build, platform and feature details."`
}

func Register(c cli.ContainerRequirementSetters, version sys.Version) {
	c.AddCommand(cli.NewCommand[opts]("version", "Show Bifröst version details.").
		WithProfiles(common.ProfileExecutable, common.ProfileManagement).
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
		return target.RunDirect(ctx, command)
	}
	f := sys.VersionFormatShort
	if o.Long {
		f = sys.VersionFormatLong
	}
	return cli.Println(ctx, sys.FormatVersion(version, f))
}
