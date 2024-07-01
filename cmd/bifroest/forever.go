package main

import (
	"github.com/alecthomas/kingpin"
	"os"
	"os/signal"
	"syscall"
)

var _ = registerCommand(func(app *kingpin.Application) {
	app.Command("forever", "This is a supporting command which simply runs forever until it receives a interrupt signal.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doForever()
		})
})

func doForever() error {
	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	return nil
}
