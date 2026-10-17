package audit

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("audit", "Inspect and verify signed audit journals.").
			WithProfiles(common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement).
			WithCommand(createBrowseCommands()...).
			WithCommand(createProducerIDCommands()...).
			WithCommand(createVerifyCommands()...).
			WithCommand(createAuditExportCommands()...).
			WithCommand(createMergeCommands()...),
	}
}
