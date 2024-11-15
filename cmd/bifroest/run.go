package main

import (
	"context"
	goos "os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/service"
)

var _ = registerCommand(func(app *kingpin.Application) {
	configureRunCmd(app)
})

func doRunDefault(conf configuration.Ref) error {
	svc := service.Service{
		Configuration: *conf.Get(),
		Version:       versionV,
	}

	fail := func(err error) error {
		log.Error(err)
		goos.Exit(1)
		return nil
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	sigs := make(chan goos.Signal, 1)
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
