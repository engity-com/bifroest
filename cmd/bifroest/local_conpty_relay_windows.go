//go:build windows

package main

import (
	goos "os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/engity-com/bifroest/pkg/environment"
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("local-conpty-relay", "Internal ConPTY relay for local shell sessions.").Hidden()
	cols := cmd.Arg("cols", "PTY columns.").Required().Int()
	rows := cmd.Arg("rows", "PTY rows.").Required().Int()
	cmd.Action(func(*kingpin.ParseContext) error {
		argv, err := environment.ReadLocalConPTYCommand(goos.Stdin)
		if err != nil {
			return err
		}
		code, err := environment.RunLocalConPTYRelay(*cols, *rows, argv)
		if err != nil {
			return err
		}
		return environment.WriteLocalConPTYRelayExitStatus(goos.Stderr, code)
	})
})
