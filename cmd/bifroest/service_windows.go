//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/service"
)

const (
	defaultServiceName = "engity-bifroest"
	serviceDisplayName = "Engity's Bifröst"
)

type windowsService struct {
	name   string
	conf   configuration.ConfigurationRef
	logger *eventlog.Log
}

func (this *windowsService) registerFlagsAt(cmd *kingpin.CmdClause) *kingpin.CmdClause {
	cmd.Flag("serviceName", "Name of the service. Default: "+defaultServiceName).
		Default(defaultServiceName).
		PlaceHolder("<name>").
		StringVar(&this.name)
	return cmd
}

var _ = registerCommand(func(app *kingpin.Application) {
	svcCmd := app.Command("service", "")

	var conf configuration.ConfigurationRef
	var svc windowsService
	common := func(cmd *kingpin.CmdClause) *kingpin.CmdClause {
		return svc.registerFlagsAt(cmd)
	}
	withConfig := func(cmd *kingpin.CmdClause) *kingpin.CmdClause {
		cmd.Flag("configuration", "Configuration which should be used to serve the service. Default: "+defaultConfigurationRef).
			Short('c').
			Default(defaultConfigurationRef).
			PlaceHolder("<path>").
			SetValue(&conf)
		return common(cmd)
	}

	start := true
	installCmd := withConfig(svcCmd.Command("install", "Installs the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.install(conf, start, true)
		}))
	installCmd.Flag("start", "If enabled, the service will be started afterwards, automatically. (Default=true)").
		BoolVar(&start)

	stop := true
	stopCmd := common(svcCmd.Command("remove", "Removes the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.remove(stop)
		}))
	stopCmd.Flag("stop", "If enabled, the service will be stopped afterwards, automatically.  (Default=true)").
		BoolVar(&stop)
	common(svcCmd.Command("start", "Starts the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.start()
		}))
	common(svcCmd.Command("stop", "Stops the service.").
		Action(func(*kingpin.ParseContext) error {
			return svc.stop()
		}))
})

func (this *windowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	s := service.Service{
		Configuration: *this.conf.Get(),
		Version:       versionV,
	}

	fail := func(err error) (ssec bool, errno uint32) {
		log.Error(err)
		return false, 1
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	go func() {
		for {
			c := <-r
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancelFunc()
			default:
				_ = this.logger.Error(1, fmt.Errorf("unexpected control request #%d", c).Error())
			}
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if err := s.Run(ctx); err != nil {
		return fail(err)
	}

	changes <- svc.Status{State: svc.StopPending}
	return false, 0
}

func (this *windowsService) install(conf configuration.ConfigurationRef, start, retry bool) error {
	if err := conf.MakeAbsolute(); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return errors.System.Newf("cannot resolve own executable: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	if s, err := m.OpenService(this.name); err == nil {
		_ = s.Close()
		if !retry {
			return errors.System.Newf("service %s already exists", this.name)
		}
		if err := this.remove(true); err != nil {
			return err
		}
		return this.install(conf, start, false)
	}

	mgrCfg := mgr.Config{
		StartType:        mgr.StartAutomatic,
		DisplayName:      serviceDisplayName,
		DelayedAutoStart: true,
	}
	success := false
	s, err := m.CreateService(this.name, exe, mgrCfg, "run", "--configuration="+conf.GetFilename())
	if err != nil {
		return err
	}
	defer common.IgnoreError(s.Close)
	defer common.IgnoreErrorIfFalse(&success, s.Delete)

	if err := eventlog.InstallAsEventCreate(this.name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		if err.Error() != "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\"+this.name+" registry key already exists" {
			return errors.System.Newf("SetupEventLogSource() failed: %w", err)
		}
	}
	defer func() {
		if !success {
			_ = eventlog.Remove(this.name)
		}
	}()

	if start {
		if err := this.start(); err != nil {
			return err
		}
	}

	success = true
	return nil
}

func (this *windowsService) remove(stop bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.name, err)
	}
	defer common.IgnoreError(s.Close)

	if stop {
		if _, err := s.Control(svc.Stop); err != nil {
			return errors.System.Newf("cannot stop service %s: %w", this.name, err)
		}
	}

	if err = s.Delete(); err != nil {
		return err
	}

	if err := eventlog.Remove(this.name); err != nil {
		return errors.System.Newf("RemoveEventLogSource() failed: %w", err)
	}
	return nil
}

func (this *windowsService) start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.name, err)
	}
	defer common.IgnoreError(s.Close)

	if err = s.Start(); err != nil {
		return errors.System.Newf("cannot start service %s: %w", this.name, err)
	}
	return nil
}

func (this *windowsService) stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.name, err)
	}
	defer common.IgnoreError(s.Close)

	if _, err := s.Control(svc.Stop); err != nil {
		return errors.System.Newf("cannot stop service %s: %w", this.name, err)
	}
	return nil
}
