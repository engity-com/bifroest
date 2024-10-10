package main

import (
	"context"

	"github.com/alecthomas/kingpin"
)

func newDependencies(b *base) *dependencies {
	result := &dependencies{
		base: b,
	}

	result.caCerts = newDependenciesCaCerts(result)
	result.imagesFiles = newDependenciesImagesFiles(result)

	return result
}

type dependencies struct {
	base *base

	caCerts     *dependenciesCaCerts
	imagesFiles *dependenciesImagesFiles
}

func (this *dependencies) init(ctx context.Context, app *kingpin.Application) {
	this.caCerts.init(ctx, app)
	this.imagesFiles.init(ctx, app)
}
