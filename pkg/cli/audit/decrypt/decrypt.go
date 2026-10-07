package decrypt

import (
	"context"
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"
	cli "github.com/echocat/cli4g"

	cexport "github.com/engity-com/bifroest/pkg/cli/audit/export"
	. "github.com/engity-com/bifroest/pkg/cli/common"
)

var remoteAuditDecryptOpts = map[string]*cexport.Opts{}

type opts struct {
}

func Register(ctx context.Context, c cli.ContainerRequirementSetters, usage Usage) {
	o := cexport.Opts{Output: "-"}
	o.commandRoot = cmds.FullCommand()
	remoteAuditDecryptOpts[cmds.FullCommand()] = &o
	cmd := cmds.Command("decrypt", "Alias for audit export (verified JSON Lines).").
		Action(func(*kingpin.ParseContext) error { return doAuditDecrypt(&o, goos.Stdout) })
	cexport.RegisterFlags(cmd, &o)
	cmd.Arg("auditlogName", "Configured auditlog, or optional label for an offline journal (default: default).").SetValue(&o.auditlog)
}

func doAuditDecrypt(opts *cexport.Opts, stdout io.Writer) error {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	return cexport.Do(opts, stdout)
}
