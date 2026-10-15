//go:build !embedded_dlv

package dlv

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
)

func Register(context.Context, cli.ContainerRequirementSetters, common.Usage) {}
