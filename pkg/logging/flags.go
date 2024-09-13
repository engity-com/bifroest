package logging

import (
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	log "github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/consumer"
	"github.com/echocat/slf4g/native/facade/value"

	"github.com/engity-com/bifroest/pkg/common"
)

type LogProvider interface {
	log.Provider
	value.ProviderTarget
	level.NamesAware
}

func ConfigureLoggingForFlags(app *kingpin.Application, of LogProvider) {
	native.DefaultProvider.Consumer = consumer.NewWriter(os.Stderr)

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

func logLevelStrings(of LogProvider) []string {
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
