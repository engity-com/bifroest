//go:build !windows && !darwin

package service

import (
	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/sys"
)

func CreateCommands(sys.Version) []cli.CommandRequirementLike { return nil }
