package cli

import (
	"context"

	"github.com/echocat/cli4g"

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
	"github.com/engity-com/bifroest/pkg/sys"
)

func registerExecutable(ctx context.Context, c cli.ContainerRequirementSetters, version sys.Version) {
	usage := common.UsageExecutable
	caudit.Register(ctx, c, usage)
	cflow.Register(ctx, c, usage)
	csession.Register(ctx, c, usage)
	crecording.Register(ctx, c, usage)
	cversion.Register(ctx, c, usage, version)
	cdlv.Register(ctx, c, usage)
	cdummyserver.Register(ctx, c, usage)
	cexec.Register(ctx, c, usage)
	cforever.Register(ctx, c, usage)
	cimp.Register(ctx, c, usage, version)
	ckey.Register(ctx, c, usage)
	cserve.Register(ctx, c, usage, version)
	cservice.Register(ctx, c, usage, version)
	csftpserver.Register(ctx, c, usage)
}
