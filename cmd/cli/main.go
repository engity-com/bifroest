package main

import (
	"github.com/engity/pam-oidc/pkg/common"
	"github.com/engity/pam-oidc/pkg/user"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g/native"
	"github.com/echocat/slf4g/native/facade/value"

	"github.com/engity/pam-oidc/pkg/core"
)

var (
	configurationRefs core.ConfigurationRefs

	socketPerm  = common.MustNewFileMode("0600")
	socketPath  = core.DefaultSocketPath
	socketUser  user.UserRef
	socketGroup user.GroupRef
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

	//registerTestFlowCmd(app)
	registerServiceCmd(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
