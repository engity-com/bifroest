package main

import (
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/configuration"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"
)

var (
	configurationRef = configuration.MustNewConfigurationRef("/etc/engity/bifroest/configuration.yaml")
	workingDir       = func() string {
		v, err := os.Getwd()
		if err == nil {
			return v
		}
		return "/"
	}()
)

func main() {
	app := kingpin.New("bifroest", "SSH server which provides authorization and authentication via OpenID Connect and classic mechanisms to access a real host or a dedicated Docker container.").
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
	registerSftpServerCmd(app)

	if _, err := app.Parse(os.Args[1:]); err != nil {
		log.WithError(err).Error("execution failed")
		os.Exit(1)
	}
}
