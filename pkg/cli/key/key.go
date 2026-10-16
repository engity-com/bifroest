package key

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	cexport "github.com/engity-com/bifroest/pkg/cli/key/export"
	cgenerate "github.com/engity-com/bifroest/pkg/cli/key/generate"
	cimport "github.com/engity-com/bifroest/pkg/cli/key/import"
)

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("key", "Generate, export and import SSH keys.").
			WithProfiles(common.ProfileExecutable).
			WithCommand(cexport.CreateCommands()...).
			WithCommand(cgenerate.CreateCommands()...).
			WithCommand(cimport.CreateCommands()...),
	}
}
