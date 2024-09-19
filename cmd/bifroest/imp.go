package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/imp"
)

var (
	impService = func() *imp.Service {
		return &imp.Service{
			Version: versionV,
		}
	}()
	encodecMasterPublicKey string
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("imp", "Runs the imp service.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doImp()
		})
	cmd.Flag("master-public-key", "Access token to accessing the imp service (hex encoded).").
		Envar("BIFROEST_MASTER_PUBLIC_KEY").
		PlaceHolder("<path>").
		Required().
		StringVar(&encodecMasterPublicKey)
})

func doImp() error {
	// TODO! Parse encodecMasterPublicKey
	panic(":encodecMasterPublicKey")

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

	var rErr atomic.Pointer[error]
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := impService.Serve(ctx); err != nil {
			rErr.CompareAndSwap(nil, &err)
		}
	}()

	log.WithAll(common.VersionToMap(versionV)).Info("Engity's Bifröst imp running...")
	wg.Wait()

	if v := rErr.Load(); v != nil {
		log.WithError(*v).Error()
		os.Exit(1)
		return nil
	}

	return nil
}
