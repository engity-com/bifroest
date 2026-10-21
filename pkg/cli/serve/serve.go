package serve

import (
	"context"
	"fmt"
	goos "os"
	"os/signal"
	"syscall"

	"github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

func doRunDefault(rc context.Context, o *opts, version sys.Version, run common.ServiceRunner) error {
	if run == nil {
		return fmt.Errorf("service runner is unavailable")
	}
	if err := configureProcessLimits(); err != nil {
		return err
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

	if err := run(ctx, *o.Configuration, version); err != nil {
		return err
	}

	return nil
}
