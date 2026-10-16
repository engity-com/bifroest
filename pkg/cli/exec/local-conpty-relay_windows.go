//go:build windows

package exec

import (
	"context"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/environment"
)

type localConPTYRelayOptions struct {
	Columns int `argument:"cols" required:"true" description:"PTY columns."`
	Rows    int `argument:"rows" required:"true" description:"PTY rows."`
}

func registerLocalConPTYRelay(parent cli.ContainerRequirementSetters) {
	parent.AddCommand(
		cli.NewCommand[localConPTYRelayOptions]("local-conpty-relay", "Internal ConPTY relay for local shell sessions.").
			WithProfiles(common.ProfileExecutable).
			WithVisible(false).
			WithHandler(func(ctx context.Context, opts localConPTYRelayOptions) error {
				argv, err := environment.ReadLocalConPTYCommand(cli.StdinOfContext(ctx))
				if err != nil {
					return err
				}
				code, err := environment.RunLocalConPTYRelay(opts.Columns, opts.Rows, argv)
				if err != nil {
					return err
				}
				return environment.WriteLocalConPTYRelayExitStatus(cli.StderrOfContext(ctx), code)
			}),
	)
}
