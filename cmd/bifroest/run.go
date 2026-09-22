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

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	sigs := make(chan goos.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case sig := <-sigs:
			log.With("signal", sig).Info("received signal")
			cancelFunc()
		case <-ctx.Done():
		}
	}()

	if err := svc.Run(ctx); err != nil {
		return err
	}

	return nil
}
