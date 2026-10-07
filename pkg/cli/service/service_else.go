//go:build !windows && !darwin

package service

import (
	"context"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

func Register(context.Context, cli.ContainerRequirementSetters, Usage, sys.Version) {}
