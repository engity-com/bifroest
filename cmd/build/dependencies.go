package main

import (
	"context"

	"github.com/alecthomas/kingpin/v2"
)

func newDependencies(b *base) *dependencies {
	result := &dependencies{
		base: b,
	}

	result.caCerts = newDependenciesCaCerts(result)

	return result
}

type dependencies struct {
	base *base

	caCerts *dependenciesCaCerts
}

func (this *dependencies) init(ctx context.Context, app *kingpin.Application) {
	this.caCerts.init(ctx, app)
}
