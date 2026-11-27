package main

import (
	"context"
	"net/http"
	"time"

	"github.com/alecthomas/kingpin/v2"
)

func newDependencies(b *base) *dependencies {
	result := &dependencies{
		base:               b,
		resolveImageDigest: resolveDependencyImageDigest,
		conptyHTTPClient:   &http.Client{Timeout: time.Minute},
		miseCommand:        runDependencyMise,
	}

	result.caCerts = newDependenciesCaCerts(result)

	return result
}

type dependencies struct {
	base *base

	caCerts            *dependenciesCaCerts
	resolveImageDigest dependencyImageDigestResolver
	conptyHTTPClient   *http.Client
	miseCommand        dependencyMiseCommand
}

func (this *dependencies) init(ctx context.Context, app *kingpin.Application) {
	this.caCerts.init(ctx, app)
	command := app.Command("dependencies", "Manage all automatically updated dependencies.")
	command.Command("update-pr", "Create one pull request for all changed managed dependencies.").
		Action(func(*kingpin.ParseContext) error {
			return this.updatePr(ctx)
		})
	command.Command("tools", "Manage the MISE tool version catalog.").
		Command("check", "Preview tool updates without editing the checkout or GitHub.").
		Action(func(*kingpin.ParseContext) error { return this.checkToolUpdates(ctx) })
}
