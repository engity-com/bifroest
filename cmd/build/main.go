package main

import (
	"context"
	gos "os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"
	"github.com/echocat/slf4g/native/facade/value"

	"github.com/engity-com/bifroest/pkg/common"
)

func main() {
	b := newBase()

	app := kingpin.New("build", "Command used only for building bifroest.").
		UsageWriter(gos.Stderr).
		ErrorWriter(gos.Stderr).
		Terminate(func(i int) {
			code := max(i, 1)
			gos.Exit(code)
		})

	configureLog(app, native.DefaultProvider)

	ctx, cancelFunc := context.WithCancel(context.Background())
	sigs := make(chan gos.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancelFunc()
	}()

	b.init(ctx, app)

	if _, err := app.Parse(gos.Args[1:]); err != nil {
		log.WithError(err).Error("execution failed")
		gos.Exit(1)
	}
}

type logProvider interface {
	log.Provider
	value.ProviderTarget
	level.NamesAware
}

func configureLog(app *kingpin.Application, of logProvider) {
	native.DefaultProvider.Consumer = consumer.NewWriter(gos.Stdout)

	if gos.Getenv("RUNNER_DEBUG") == "1" {
		of.SetLevel(level.Debug)
	}

	lv := value.NewProvider(of)
	app.Flag("log.level", "Defines the minimum level at which the log messages will be logged. Default: "+lv.Level.String()).
		PlaceHolder("<" + strings.Join(logLevelStrings(of), "|") + ">").
		SetValue(lv.Level)
	app.Flag("log.colorMode", "Tells if to log in color or not. Default: "+lv.Consumer.Formatter.ColorMode.String()).
		PlaceHolder("<auto|always|never>").
		SetValue(lv.Consumer.Formatter.ColorMode)
}

func logLevelStrings(of logProvider) []string {
	names := of.GetLevelNames()

	lvls := of.GetAllLevels()
	all := make([]string, len(lvls))
	for i, lvl := range lvls {
		name, err := names.ToName(lvl)
		common.Must(err)
		all[i] = name
	}
	return all
}
