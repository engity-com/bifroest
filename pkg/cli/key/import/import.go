package _import

import (
	"context"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(ctx context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("import").
		WithDescription("Import trusted SSH public key material.")

	registerCa(ctx, cmd, usage)
	registerHost(ctx, cmd, usage)

	c.AddCommand(cmd)
}
