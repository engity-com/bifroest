package _import

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(c cli.ContainerRequirementSetters) {
	cmd := cli.NewSimpleCommand("import", "Import trusted SSH public key material.").
		WithProfiles(common.ProfileExecutable)

	registerCa(cmd)
	registerHost(cmd)

	c.AddCommand(cmd)
}
