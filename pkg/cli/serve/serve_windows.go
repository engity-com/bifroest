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

	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/logging/wel"
	"github.com/engity-com/bifroest/pkg/sys"
)

type opts struct {
	configuration.Opts
	cservice.BaseOpts
	WindowsService bool `flag:"windowsService" default:"false" description:"Run as an explicitly registered Windows SCM service; do not rely on parent-process detection."`
}

func CreateCommands(version sys.Version, run cliCommon.ServiceRunner) []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[*opts]("serve", "Runs the service.").
			WithProfiles(cliCommon.ProfileExecutable).
			WithAliases("run").
			WithHandler(func(ctx context.Context, o *opts) error {
				return doRun(ctx, o, version, run)
			}),
	}
}

func windowsServiceMode(explicit bool, detect func() (bool, error)) (bool, error) {
	if explicit {
		return true, nil
	}
	return detect()
}

func doRun(ctx context.Context, o *opts, version sys.Version, run cliCommon.ServiceRunner) error {
	inService, err := windowsServiceMode(o.WindowsService, svc.IsWindowsService)
	if err != nil {
		return errors.System.Newf("failed to determine if we are running in service: %w", err)
	}
	if !inService {
		return doRunDefault(ctx, o, version, run)
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
		Conf:    *o.Configuration,
		Logger:  eLog,
		Run:     run,
	}
	if err := svc.Run(ws.Name, ws); err != nil {
		return errors.System.Newf("cannot run Windows SCM service %s: %w", ws.Name, err)
	}
	return nil
}
