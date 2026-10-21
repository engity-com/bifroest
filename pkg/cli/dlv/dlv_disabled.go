//go:build !embedded_dlv

package dlv

import cli "github.com/echocat/cli4g"

func CreateCommands() []cli.CommandRequirementLike { return nil }
