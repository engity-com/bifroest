package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/imp"
)

var (
	socks5Service imp.Service
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("imp", "Runs the imp service.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doImp()
		})
	cmd.Flag("access-token", "Access token to accessing the imp service.").
		Envar("BIFROEST_IMP_ACCESS_TOKEN").
		PlaceHolder("<path>").
		Required().
		StringVar(&socks5Service.AccessToken)
	cmd.Flag("socks5-address", "Address where the imp is serving its socks5 server.").
		Default(":8000").
		PlaceHolder("[<host>]:<port>").
		StringVar(&socks5Service.Address)
})

func doImp() error {
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
		if err := socks5Service.Run(ctx); err != nil {
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
