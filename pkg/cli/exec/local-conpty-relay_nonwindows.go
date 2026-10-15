//go:build !windows

package exec

import cli "github.com/echocat/cli4g"

func registerLocalConPTYRelay(cli.ContainerRequirementSetters) {}
