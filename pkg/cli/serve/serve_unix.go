//go:build unix

package serve

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	configuration.Opts
}

func Register(c cli.ContainerRequirementSetters, version sys.Version, run common.ServiceRunner) {
	c.AddCommand(cli.NewCommand[*opts]("serve", "Runs the service.").
		WithProfiles(common.ProfileExecutable).
		WithAliases("run").
		WithHandler(func(ctx context.Context, o *opts) error {
			return doRunDefault(ctx, o, version, run)
		}),
	)
}
