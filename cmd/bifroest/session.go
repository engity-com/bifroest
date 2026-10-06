package main

import (
	"context"
	"fmt"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = registerCommand(func(app *kingpin.Application) {
	management.RegisterSessionCommands(app, func(ctx context.Context, path string, consumer func(context.Context, session.Info) (bool, error), diagnostics session.FindDiagnosticConsumer) error {
		if path == "" {
			path = defaultConfigurationRef
		}
		var ref configuration.Ref
		if err := ref.Set(path); err != nil {
			return err
		}
		fs, ok := ref.Get().Session.V.(*configuration.SessionFs)
		if !ok {
			return fmt.Errorf("local inspection does not support session repository %T", ref.Get().Session.V)
		}
		return session.InspectFsSessions(ctx, fs.Storage, consumer, diagnostics)
	}, context.Background(), goos.Stdout, goos.Stderr, true)
})
