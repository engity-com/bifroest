package management

import (
	"context"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"

	"github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/flow"
	"github.com/engity-com/bifroest/pkg/cli/recording"
	"github.com/engity-com/bifroest/pkg/cli/session"
	"github.com/engity-com/bifroest/pkg/cli/version"
	"github.com/engity-com/bifroest/pkg/sys"
)

// NewApplication compiles the restricted schema once. Its handlers obtain
// authorization, repositories and streams from each SSH invocation's context.
func NewApplication(build sys.Version) (*cli.Application[cli.NoOptions], error) {
	requirement := cli.NewSimpleApplication().
		WithName("bifroest").
		WithDescription("Bifröst SSH management.").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339")
	audit.Register(context.Background(), requirement, common.UsageManagement)
	flow.Register(context.Background(), requirement, common.UsageManagement)
	recording.Register(context.Background(), requirement, common.UsageManagement)
	session.Register(context.Background(), requirement, common.UsageManagement)
	version.Register(context.Background(), requirement, common.UsageManagement, build)
	return requirement.Create()
}
