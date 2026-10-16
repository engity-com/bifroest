package export

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(c cli.ContainerRequirementSetters) {
	cmd := cli.NewSimpleCommand("export", "Export SSH public key material.").
		WithProfiles(common.ProfileExecutable)

	registerPublic(cmd)
	registerCa(cmd)
	registerHost(cmd)

	c.AddCommand(cmd)
}
