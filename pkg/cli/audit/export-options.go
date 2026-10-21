package audit

type OutputOpts struct {
	Output string `flag:"output" default:"-" placeholder:"<path|->" description:"Output file (its parent must exist) or - for stdout."`
	Force  bool   `flag:"force" description:"Replace an existing output file."`
}
