package audit

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func registerDecrypt(parent cli.ContainerRequirementSetters, usage common.Usage) {
	if usage == common.UsageManagement {
		parent.AddCommand(
			cli.NewCommand[managementExportOptions]().
				WithName("decrypt").
				WithDescription("Alias for audit export (verified JSON Lines).").
				WithHandler(handleManagementExport),
		)
		return
	}
	parent.AddCommand(cli.NewCommand[exportOptions]().
		WithName("decrypt").
		WithDescription("Alias for audit export (verified JSON Lines).").
		WithHandler(handleAuditExport))
}
