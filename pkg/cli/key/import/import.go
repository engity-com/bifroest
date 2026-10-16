package _import

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("import", "Import trusted SSH public key material.").
			WithProfiles(common.ProfileExecutable).
			WithCommand(createCaCommands()...).
			WithCommand(createHostCommands()...),
	}
}
