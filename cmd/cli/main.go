package main

import (
	"github.com/engity-com/yasshd/pkg/configuration"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"
)

var (
	configurationRef = configuration.MustNewConfigurationRef("/etc/yasshd/configuration.yaml")
)

func main() {
	app := kingpin.New("yasshd-cli", "Cli to manage yasshd").
		UsageWriter(os.Stderr).
		ErrorWriter(os.Stderr).
		Terminate(func(i int) {
			code := max(i, 1)
			os.Exit(code)
		})

	lv := value.NewProvider(native.DefaultProvider)
	app.Flag("log.level", "").SetValue(lv.Level)
	app.Flag("log.format", "").SetValue(lv.Consumer.Formatter)
	app.Flag("log.colorMode", "").SetValue(lv.Consumer.Formatter.ColorMode)

	registerRunCmd(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
