package audit

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func registerDecrypt(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(
		cli.NewCommand[managementExportOptions]("decrypt", "Alias for audit export (verified JSON Lines).").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementExport),
	)
	parent.AddCommand(
		cli.NewCommand[exportOptions]("decrypt", "Alias for audit export (verified JSON Lines).").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleAuditExport),
	)
}
