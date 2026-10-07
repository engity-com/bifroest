package common

import "github.com/alecthomas/kingpin/v2"

type Commands interface {
	Command(name, help string) *kingpin.CmdClause
	Flags
}

type Flags interface {
	Flag(name, help string) *kingpin.FlagClause
}
