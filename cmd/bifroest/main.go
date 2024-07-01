package main

import (
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native/consumer"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"os"
	"strings"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"
)

const (
	defaultConfigurationRef = "/etc/engity/bifroest/configuration.yaml"
)

var (
	configurationRef configuration.ConfigurationRef
	registerCommands []func(*kingpin.Application)
)

func registerCommand(rc func(*kingpin.Application)) func(*kingpin.Application) {
	registerCommands = append(registerCommands, rc)
	return rc
}

func main() {
	app := kingpin.New("bifroest", "SSH server which provides authorization and authentication via OpenID Connect and classic mechanisms to access a real host or a dedicated Docker container.").
		UsageWriter(os.Stderr).
		ErrorWriter(os.Stderr).
		Terminate(func(i int) {
			code := max(i, 1)
			os.Exit(code)
		})

	configureLog(app, native.DefaultProvider)

	for _, rc := range registerCommands {
		rc(app)
	}

	if _, err := app.Parse(os.Args[1:]); err != nil {
		log.WithError(err).Error("execution failed")
		os.Exit(1)
	}
}

type logProvider interface {
	log.Provider
	value.ProviderTarget
	level.NamesAware
}

func configureLog(app *kingpin.Application, of logProvider) {
	native.DefaultProvider.Consumer = consumer.NewWriter(os.Stdout)

	lv := value.NewProvider(of)
	app.Flag("log.level", "Defines the minimum level at which the log messages will be logged. Default: "+lv.Level.String()).
		PlaceHolder("<" + strings.Join(logLevelStrings(of), "|") + ">").
		SetValue(lv.Level)
	app.Flag("log.format", "In which format the log output should be printed. Default: "+lv.Consumer.Formatter.String()).
		PlaceHolder("<" + strings.Join(logFormatStrings(), "|") + ">").
		SetValue(lv.Consumer.Formatter)
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

func logFormatStrings() []string {
	codecs := value.DefaultFormatterCodec.(value.MappingFormatterCodec)
	all := make([]string, len(codecs))
	var i int
	for k := range codecs {
		all[i] = k
		i++
	}
	return all
}
