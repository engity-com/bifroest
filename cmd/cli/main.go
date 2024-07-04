package main

import (
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"

	"github.com/engity/pam-oidc/pkg/core"
)

var (
	configurationRef  core.ConfigurationRef
	requestedUsername string
)

func main() {
	app := kingpin.New("pam-oidc-cli", "Cli to manage pam-oidc").
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

	registerTestFlowCmd(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
