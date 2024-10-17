package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/service"
)

var (
	configurationRef configuration.ConfigurationRef
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("run", "Runs the service.").
		Action(func(*kingpin.ParseContext) error {
			return doRun()
		})
	cmd.Flag("configuration", "Configuration which should be used to serve the service. Default: "+defaultConfigurationRef).
		Short('c').
		Default(defaultConfigurationRef).
		PlaceHolder("<path>").
		SetValue(&configurationRef)
})

func doRun() error {
	svc := service.Service{
		Configuration: *configurationRef.Get(),
		Version:       versionV,
	}

	fail := func(err error) error {
		log.Error(err)
		os.Exit(1)
		return nil
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.With("signal", sig).Info("received signal")
		cancelFunc()
	}()

	if err := svc.Run(ctx); err != nil {
		return fail(err)
	}

	return nil
}
