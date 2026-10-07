//go:build !embedded_dlv

package dlv

import (
	. "github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(cmds Commands, _ Usage) {}
