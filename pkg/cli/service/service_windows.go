//go:build windows

package service

import (
	"context"
	"fmt"
	goos "os"
	"path/filepath"
	"time"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type WindowsService struct {
	Version sys.Version
	Run     cliCommon.ServiceRunner

	Name   string
	Conf   configuration.Configuration
	Logger *eventlog.Log
}

type BaseOpts struct {
	ServiceName string `flag:"serviceName" default:"engity-bifroest" placeholder:"<name>" description:"Name of the service."`
}

type opts struct {
	BaseOpts
}

type installOpts struct {
	opts
	configuration.Opts
	Start       bool   `flag:"start" default:"true" description:"If enabled, the service will be started afterwards, automatically."`
	DisplayName string `flag:"displayName" default:"Engity's Bifröst" description:"Defines how this service is displayed in the service listings."`
}

type removeOpts struct {
	opts
	Stop bool `flag:"stop" default:"true" description:"If enabled, the service will be stopped afterwards, automatically."`
}

func CreateCommands(version sys.Version) []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("service").
			WithProfiles(cliCommon.ProfileExecutable).
			WithCommand(
				cli.NewCommand[installOpts]("install", "Installs the service.").
					WithProfiles(cliCommon.ProfileExecutable).
					WithHandler(func(_ context.Context, o installOpts) error {
						return (&WindowsService{
							Version: version,
							Name:    o.ServiceName,
							Conf:    *o.Configuration,
						}).install(o.Start, true, o.DisplayName)
					}),
				cli.NewCommand[removeOpts]("remove", "Removes the service.").
					WithProfiles(cliCommon.ProfileExecutable).
					WithHandler(func(_ context.Context, o removeOpts) error {
						return (&WindowsService{
							Version: version,
							Name:    o.ServiceName,
						}).remove(o.Stop)
					}),
				cli.NewCommand[opts]("start", "Starts the service.").
					WithProfiles(cliCommon.ProfileExecutable).
					WithHandler(func(_ context.Context, o opts) error {
						return (&WindowsService{
							Version: version,
							Name:    o.ServiceName,
						}).start()
					}),
				cli.NewCommand[opts]("stop", "Stops the service.").
					WithProfiles(cliCommon.ProfileExecutable).
					WithHandler(func(_ context.Context, o opts) error {
						return (&WindowsService{
							Version: version,
							Name:    o.ServiceName,
						}).stop()
					}),
			),
	}
}

func (this *WindowsService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

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
				_ = this.Logger.Error(1, fmt.Errorf("unexpected control request #%d", c).Error())
			}
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	if this.Run == nil {
		return fail(fmt.Errorf("service runner is unavailable"))
	}
	if err := this.Run(ctx, this.Conf, this.Version); err != nil {
		return fail(err)
	}

	changes <- svc.Status{State: svc.StopPending}
	return false, 0
}

func (this *WindowsService) install(start, retry bool, displayName string) error {
	var err error
	confFn := this.Conf.Filename
	if confFn == "" {
		return errors.System.Newf("require a configuration with filename; but got empty")
	}
	if confFn, err = filepath.Abs(confFn); err != nil {
		return errors.System.Newf("cannot make filename of configuration %q absolute: %w", confFn, err)
	}
	if displayName == "" {
		displayName = "Engity's Bifröst"
	}

	exe, err := goos.Executable()
	if err != nil {
		return errors.System.Newf("cannot resolve own executable: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	if s, err := m.OpenService(this.Name); err == nil {
		_ = s.Close()
		if !retry {
			return errors.System.Newf("service %s already exists", this.Name)
		}
		if err := this.remove(true); err != nil {
			return err
		}
		return this.install(start, false, displayName)
	}

	mgrCfg := mgr.Config{
		StartType:        mgr.StartAutomatic,
		DisplayName:      displayName,
		DelayedAutoStart: true,
	}
	success := false
	s, err := m.CreateService(this.Name, exe, mgrCfg, windowsServiceArguments(confFn, this.Name)...)
	if err != nil {
		return err
	}
	defer common.IgnoreError(s.Close)
	defer common.IgnoreErrorIfFalse(&success, s.Delete)

	if err := eventlog.InstallAsEventCreate(this.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		if err.Error() != "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\"+this.Name+" registry key already exists" {
			return errors.System.Newf("SetupEventLogSource() failed: %w", err)
		}
	}
	defer func() {
		if !success {
			_ = eventlog.Remove(this.Name)
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

func windowsServiceArguments(configurationFile, name string) []string {
	return []string{"run", "--configuration=" + configurationFile, "--windowsService", "--serviceName=" + name}
}

func (this *WindowsService) remove(stop bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.Name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.Name, err)
	}
	defer common.IgnoreError(s.Close)

	if stop {
		if _, err := s.Control(svc.Stop); err != nil {
			return errors.System.Newf("cannot stop service %s: %w", this.Name, err)
		}
	}

	if err = s.Delete(); err != nil {
		return err
	}

	if err := eventlog.Remove(this.Name); err != nil {
		return errors.System.Newf("RemoveEventLogSource() failed: %w", err)
	}
	return nil
}

func (this *WindowsService) start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.Name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.Name, err)
	}
	defer common.IgnoreError(s.Close)

	if err = s.Start(); err != nil {
		return errors.System.Newf("cannot start service %s: %w", this.Name, err)
	}
	return nil
}

func (this *WindowsService) stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer common.IgnoreError(m.Disconnect)

	s, err := m.OpenService(this.Name)
	if err != nil {
		return errors.System.Newf("cannot access service %s: %w", this.Name, err)
	}
	defer common.IgnoreError(s.Close)

	if _, err := s.Control(svc.Stop); err != nil {
		return errors.System.Newf("cannot stop service %s: %w", this.Name, err)
	}
	return nil
}
