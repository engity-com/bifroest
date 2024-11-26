//go:build windows

package main

import (
	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/native"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/logging/wel"
)

const (
	defaultConfigurationRef = `C:\ProgramData\Engity\Bifroest\configuration.yaml`
)

func configureRunCmd(app *kingpin.Application) *kingpin.Application {
	var ws windowsService
	var conf configuration.Ref
	cmd := app.Command("run", "Runs the service.").
		Action(func(*kingpin.ParseContext) error {
			return doRun(conf, &ws)
		})
	cmd.Flag("configuration", "Configuration which should be used to serve the service. Default: "+defaultConfigurationRef).
		Short('c').
		Default(defaultConfigurationRef).
		PlaceHolder("<path>").
		SetValue(&conf)
	ws.registerFlagsAt(cmd)
	return app

}

func doRun(conf configuration.Ref, ws *windowsService) error {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return errors.System.Newf("failed to determine if we are running in service: %w", err)
	}
	if !inService {
		return doRunDefault(conf)
	}

	eLog, err := eventlog.Open(ws.name)
	if err != nil {
		return errors.System.Newf("cannot open event log for service %s: %w", ws.name, err)
	}
	defer common.IgnoreCloseError(eLog)

	originalProvider := log.GetProvider()
	defer log.SetProvider(originalProvider)

	welProvider := wel.NewProvider("eventlog", eLog, native.DefaultProvider.GetLevel())
	log.SetProvider(welProvider)

	ws.conf = conf
	ws.logger = eLog
	if err := svc.Run(ws.name, ws); err != nil {
		log.WithError(err).Error()
	}
	return nil
}
