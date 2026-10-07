package key

import (
	"context"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	cexport "github.com/engity-com/bifroest/pkg/cli/key/export"
	cgenerate "github.com/engity-com/bifroest/pkg/cli/key/generate"
	cimport "github.com/engity-com/bifroest/pkg/cli/key/import"
)

func Register(ctx context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("key").
		WithDescription("Generate, export and import SSH keys.")

	cexport.Register(ctx, cmd, usage)
	cgenerate.Register(ctx, cmd, usage)
	cimport.Register(ctx, cmd, usage)

	c.AddCommand(cmd)
}
