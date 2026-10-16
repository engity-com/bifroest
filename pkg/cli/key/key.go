package key

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	cexport "github.com/engity-com/bifroest/pkg/cli/key/export"
	cgenerate "github.com/engity-com/bifroest/pkg/cli/key/generate"
	cimport "github.com/engity-com/bifroest/pkg/cli/key/import"
)

func Register(c cli.ContainerRequirementSetters) {
	cmd := cli.NewSimpleCommand("key", "Generate, export and import SSH keys.").
		WithProfiles(common.ProfileExecutable)

	cexport.Register(cmd)
	cgenerate.Register(cmd)
	cimport.Register(cmd)

	c.AddCommand(cmd)
}
