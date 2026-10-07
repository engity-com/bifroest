package audit

import (
	"context"

	cli "github.com/echocat/cli4g"

	cdecrypt "github.com/engity-com/bifroest/pkg/cli/audit/decrypt"
	cexport "github.com/engity-com/bifroest/pkg/cli/audit/export"
	"github.com/engity-com/bifroest/pkg/cli/audit/merge"
	cproducerid "github.com/engity-com/bifroest/pkg/cli/audit/producer-id"
	cverify "github.com/engity-com/bifroest/pkg/cli/audit/verify"
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/management"
)

func Register(ctx context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("audit").
		WithDescription("Identify, verify, decrypt, export and merge audit journals.")

	registerCmd(ctx, cmd, usage)

	c.AddCommand(cmd)
}

func registerCmd(ctx context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	cproducerid.Register(ctx, c, usage)
	cverify.Register(ctx, c, usage)
	cdecrypt.Register(ctx, c, usage)
	cexport.Register(ctx, c, usage)
	merge.Register(ctx, c, usage)
}

func selectedAuditFormat(root string, ownFormat format.Format) management.Format {
	if root == "auditlog" && main.remoteAuditEventsOpts != nil && main.remoteAuditEventsOpts.Format != "" {
		return management.Format(main.remoteAuditEventsOpts.Format)
	}
	if ownFormat != "" {
		return management.Format(ownFormat)
	}
	return management.FormatTable
}
