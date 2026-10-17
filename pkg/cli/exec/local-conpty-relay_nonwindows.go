//go:build !windows

package exec

import cli "github.com/echocat/cli4g"

func createLocalConPTYRelayCommands() []cli.CommandRequirementLike { return nil }
