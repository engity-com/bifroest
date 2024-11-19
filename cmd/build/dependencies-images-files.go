package main

import (
	"context"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/sys"
)

func newDependenciesImagesFiles(b *dependencies) *dependenciesImagesFiles {
	return &dependenciesImagesFiles{
		dependencies:         b,
		cacheDirectory:       images.DefaultDependenciesCacheDirectory,
		imageWithNetapi32Dll: images.ImageContainingNetapi32Dll,
	}
}

type dependenciesImagesFiles struct {
	dependencies *dependencies

	cacheDirectory       string
	alwaysRefresh        bool
	imageWithNetapi32Dll string
}

func (this *dependenciesImagesFiles) init(_ context.Context, app *kingpin.Application) {
	app.Flag("dependenciesImagesCacheDirectory", "").
		Default(this.cacheDirectory).
		StringVar(&this.cacheDirectory)
	app.Flag("dependenciesImagesAlwaysRefresh", "").
		BoolVar(&this.alwaysRefresh)
	app.Flag("dependenciesImageWithNetapi32Dll", "").
		Default(this.imageWithNetapi32Dll).
		StringVar(&this.imageWithNetapi32Dll)
}

func (this *dependenciesImagesFiles) downloadFilesFor(ctx context.Context, os sys.Os, arch sys.Arch) (result images.FileDependencies, err error) {
	return images.FetchDependencies(ctx, images.FetchDependenciesRequest{
		Os:                   os,
		Arch:                 arch,
		CacheDirectory:       this.cacheDirectory,
		AlwaysRefresh:        this.alwaysRefresh,
		ImageWithNetapi32Dll: this.imageWithNetapi32Dll,
	})
}
