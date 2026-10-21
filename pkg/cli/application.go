package cli

import (
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"

	caudit "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	cdlv "github.com/engity-com/bifroest/pkg/cli/dlv"
	cdummyserver "github.com/engity-com/bifroest/pkg/cli/dummy-server"
	cexec "github.com/engity-com/bifroest/pkg/cli/exec"
	cflow "github.com/engity-com/bifroest/pkg/cli/flow"
	cforever "github.com/engity-com/bifroest/pkg/cli/forever"
	cimp "github.com/engity-com/bifroest/pkg/cli/imp"
	ckey "github.com/engity-com/bifroest/pkg/cli/key"
	crecording "github.com/engity-com/bifroest/pkg/cli/recording"
	cserve "github.com/engity-com/bifroest/pkg/cli/serve"
	cservice "github.com/engity-com/bifroest/pkg/cli/service"
	csession "github.com/engity-com/bifroest/pkg/cli/session"
	csftpserver "github.com/engity-com/bifroest/pkg/cli/sftp-server"
	cversion "github.com/engity-com/bifroest/pkg/cli/version"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

// NewApplication registers all commands once. The selected profile determines
// which commands are available per invocation. The executable supplies run;
// management invocations cannot activate serve.
func NewApplication[O any](version sys.Version, description string, run common.ServiceRunner) *clibase.ApplicationRequirement[O] {
	return clibase.NewApplication[O]().
		WithName("bifroest").
		WithDescription(description).
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339").
		WithCommand(caudit.CreateCommands()...).
		WithCommand(cflow.CreateCommands()...).
		WithCommand(csession.CreateCommands()...).
		WithCommand(crecording.CreateCommands()...).
		WithCommand(cversion.CreateCommands(version)...).
		WithCommand(cdlv.CreateCommands()...).
		WithCommand(cdummyserver.CreateCommands()...).
		WithCommand(cexec.CreateCommands()...).
		WithCommand(cforever.CreateCommands()...).
		WithCommand(cimp.CreateCommands(version)...).
		WithCommand(ckey.CreateCommands()...).
		WithCommand(cserve.CreateCommands(version, run)...).
		WithCommand(cservice.CreateCommands(version)...).
		WithCommand(csftpserver.CreateCommands()...)
}
