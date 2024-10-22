package main

import (
	goos "os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
)

var _ = registerCommand(func(app *kingpin.Application) {
	app.Command("forever", "This is a supporting command which simply runs forever until it receives a interrupt signal.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doForever()
		})
})

func doForever() error {
	sigs := make(chan goos.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	return nil
}
