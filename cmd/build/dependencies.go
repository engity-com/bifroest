package main

import (
	"context"

	"github.com/alecthomas/kingpin/v2"
)

func newDependencies(b *base) *dependencies {
	result := &dependencies{
		base:               b,
		resolveImageDigest: resolveDependencyImageDigest,
	}

	result.caCerts = newDependenciesCaCerts(result)

	return result
}

type dependencies struct {
	base *base

	caCerts            *dependenciesCaCerts
	resolveImageDigest dependencyImageDigestResolver
}

func (this *dependencies) init(ctx context.Context, app *kingpin.Application) {
	this.caCerts.init(ctx, app)
	app.Command("dependencies", "Manage all automatically updated dependencies.").
		Command("update-pr", "Create one pull request for all changed managed dependencies.").
		Action(func(*kingpin.ParseContext) error {
			return this.updatePr(ctx)
		})
}
