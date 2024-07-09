package main

import (
	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/engity/pam-oidc/pkg/core"
	"os"
)

func registerServiceCmd(app *kingpin.Application) {
	cmd := app.Command("service", "Runs the service which is required to operate the PAM modules.").
		Action(func(*kingpin.ParseContext) error {
			return doService()
		})
	cmd.Arg("configuration", `Configuration(s) which should be used to test the flow. 
Can be defined multiple times or with several entries separated by ",". 
Each entry can have the syntax: [<key>:]<path> Each key needs to be unique. 
If no key is provided "default" will be used.`).
		Required().
		SetValue(&configurationRefs)
	cmd.Flag("socket", "Where this service binds itself to.").
		Default(socketPath).
		StringVar(&socketPath)
	cmd.Flag("socket.user", "User of the resulting socket").
		SetValue(&socketUser)
	cmd.Flag("socket.group", "Group of the resulting socket").
		SetValue(&socketGroup)
	cmd.Flag("socket.perm", "Permission of the resulting socket.").
		Default(socketPerm.String()).
		SetValue(&socketPerm)
}

func doService() error {
	svc := core.Service{
		Configurations: configurationRefs,
		SocketPerm:     socketPerm.Get(),
		SocketPath:     socketPath,
		SocketUser:     socketUser.Get(),
		SocketGroup:    socketGroup.Get(),
	}

	fail := func(err error) error {
		log.Error(err)
		os.Exit(1)
		return nil
	}

	if err := svc.Run(); err != nil {
		return fail(err)
	}

	return nil
}
