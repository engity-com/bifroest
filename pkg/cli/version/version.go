package version

import (
	"context"
	"strconv"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Long bool `flag:"long" default:"true" description:"Include build, platform and feature details."`
}

func CreateCommands(version sys.Version) []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[opts]("version", "Show Bifröst version details.").
			WithProfiles(common.ProfileExecutable, common.ProfileManagement).
			WithHandler(func(ctx context.Context, o opts) error {
				return handle(ctx, o, version)
			}),
		cli.NewCommand[opts]("version", "Show Bifröst version details.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandle),
	}
}

func handle(ctx context.Context, o opts, version sys.Version) error {
	f := sys.VersionFormatShort
	if o.Long {
		f = sys.VersionFormatLong
	}
	return cli.Println(ctx, sys.FormatVersion(version, f))
}

func remoteHandle(ctx context.Context, o opts) error {
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.RunDirect(ctx, "version --long="+strconv.FormatBool(o.Long))
}
