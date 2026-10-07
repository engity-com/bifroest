package common

import (
	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/management"
)

func RegisterAuditSensitiveFlag(flags Flags, target *bool) {
	management.AuditSensitiveFlag(flags, target)
}

type OutputOpts struct {
	Output string `flag:"output" default:"-" placeholder:"<path|->" description:"Output file (its parent must exist) or - for stdout."`
	Force  bool   `flag:"force" description:"Replace an existing output file."`
}

func RegisterAuditOutputFlags(flags Flags, output *string, force *bool) {
	flags.Flag("output", "Output file (its parent must exist) or - for stdout.").
		Default("-").
		PlaceHolder("<path|->").
		StringVar(output)
	flags.Flag("force", "Replace an existing output file.").
		BoolVar(force)
}
