//go:build !windows && !darwin

package service

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/sys"
)

func Register(cli.ContainerRequirementSetters, sys.Version) {}
