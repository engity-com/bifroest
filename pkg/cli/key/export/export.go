package export

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(ctx context.Context, c cli.ContainerRequirementSetters, usage common.Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("export").
		WithDescription("Export SSH public key material.")

	registerPublic(ctx, cmd, usage)
	registerCa(ctx, cmd, usage)
	registerHost(ctx, cmd, usage)

	c.AddCommand(cmd)
}
