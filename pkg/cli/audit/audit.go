package audit

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(c cli.ContainerRequirementSetters) {
	cmd := cli.NewSimpleCommand("audit", "Inspect and verify signed audit journals.").
		WithProfiles(common.ProfileExecutable, common.ProfileManagement)

	registerBrowse(cmd)
	registerProducerID(cmd)
	registerVerify(cmd)
	registerDecrypt(cmd)
	registerAuditExport(cmd)
	registerMerge(cmd)

	c.AddCommand(cmd)
}
