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

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage common.Usage, version sys.Version) {
	if !usage.IncludeService() {
		return
	}

	c.AddCommand(cli.NewCommand[*opts]().
		WithName("serve", "run").
		WithDescription("Runs the service.").
		WithHandler(func(ctx context.Context, o *opts) error {
			return doRunDefault(ctx, o, version)
		}),
	)
}
