//go:build windows

package serve

import (
	"context"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/native"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	cservice "github.com/engity-com/bifroest/pkg/cli/service"
	"github.com/engity-com/bifroest/pkg/configuration"

	. "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/logging/wel"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	configuration.Opts
	cservice.BaseOpts
}

func Register(_ context.Context, c cli.ContainerRequirementSetters, usage Usage, version sys.Version) {
	if !usage.IncludeService() {
		return
	}

	c.AddCommand(cli.NewCommand[*opts]().
		WithName("serve", "run").
		WithDescription("Runs the service.").
		WithHandler(func(ctx context.Context, o *opts) error {
			return doRun(ctx, o, version)
		}),
	)
}

func doRun(ctx context.Context, o *opts, version sys.Version) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return errors.System.Newf("failed to determine if we are running in service: %w", err)
	}
	if !inService {
		return doRunDefault(ctx, o, version)
	}

	eLog, err := eventlog.Open(o.ServiceName)
	if err != nil {
		return errors.System.Newf("cannot open event log for service %s: %w", o.ServiceName, err)
	}
	defer common.IgnoreCloseError(eLog)

	originalProvider := log.GetProvider()
	defer log.SetProvider(originalProvider)

	welProvider := wel.NewProvider("eventlog", eLog, native.DefaultProvider.GetLevel())
	log.SetProvider(welProvider)

	ws := &cservice.WindowsService{
		Version: version,
		Name:    o.ServiceName,
		Conf:    o.Configuration,
		Logger:  eLog,
	}
	if err := svc.Run(ws.Name, ws); err != nil {
		log.WithError(err).Error()
	}
	return nil
}
