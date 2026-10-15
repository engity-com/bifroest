package audit

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage common.Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("audit").
		WithDescription("Inspect and verify signed audit journals.")

	registerBrowse(cmd, usage)
	registerProducerID(cmd, usage)
	registerVerify(cmd, usage)
	registerDecrypt(cmd, usage)
	registerAuditExport(cmd, usage)
	registerMerge(cmd, usage)

	c.AddCommand(cmd)
}
