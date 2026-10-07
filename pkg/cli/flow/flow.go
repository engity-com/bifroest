package flow

import (
	goos "os"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/management"
)

func Register(cmds Commands, _ Usage) {
	management.RegisterFlowCommands(cmds, LoadManagementConfiguration, goos.Stdout, false, true)
}
