package serve

import (
	"context"
	goos "os"
	"os/signal"
	"syscall"

	"github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/service"
	"github.com/engity-com/bifroest/pkg/sys"
)

func doRunDefault(rc context.Context, o *opts, version sys.Version) error {
	if err := configureProcessLimits(); err != nil {
		return err
	}
	svc := service.Service{
		Configuration: o.Configuration,
		Version:       version,
	}

	ctx, cancelFunc := context.WithCancel(rc)
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
