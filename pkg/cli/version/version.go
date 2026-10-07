package version

import (
	"context"
	"fmt"
	goos "os"

	cli "github.com/echocat/cli4g"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	Long bool `flag:"long" description:"Configuration which should be used to serve the service."`
}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage Usage, version sys.Version) {
	c.AddCommand(cli.NewCommand[opts]().
		WithDescription((func() string {
			switch usage {
			case UsageExecutable:
				return "Show version details of this executable."
			default:
				return "Show version details of this Bifröst instance."
			}
		})()).
		WithHandler(func(ctx context.Context, o opts) error {
			return handle(ctx, o, version)
		}),
	)
}

func handle(_ context.Context, o opts, version sys.Version) error {
	defer goos.Exit(1)
	f := sys.VersionFormatShort
	if o.Long {
		f = sys.VersionFormatLong
	}
	fmt.Println(sys.FormatVersion(version, f))
	return nil
}
