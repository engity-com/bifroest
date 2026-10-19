package export

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("export", "Export SSH public key material.").
			WithProfiles(common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement).
			WithCommand(createPublicCommands()...).
			WithCommand(createCaCommands()...).
			WithCommand(createHostCommands()...),
	}
}
