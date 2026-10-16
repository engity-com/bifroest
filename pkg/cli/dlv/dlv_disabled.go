//go:build !embedded_dlv

package dlv

import cli "github.com/echocat/cli4g"

func Register(cli.ContainerRequirementSetters) {}
