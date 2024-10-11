package main

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	gos "os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/mr-tron/base58"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	netapi32DllFilename = `C:\Windows\System32\netapi32.dll`
)

func newDependenciesImagesFiles(b *dependencies) *dependenciesImagesFiles {
	return &dependenciesImagesFiles{
		dependencies:         b,
		cacheDirectory:       filepath.Join(".cache", "dependencies", "images"),
		imageWithNetapi32Dll: "mcr.microsoft.com/windows/servercore:ltsc2022",
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

func (this *dependenciesImagesFiles) downloadFilesFor(ctx context.Context, os os, arch arch) (result []imageFileDependency, err error) {
	v, err := this.downloadNetapi32DllFor(ctx, os, arch)
	if err != nil {
		return nil, err
	}
	result = append(result, v...)

	return result, nil
}

func (this *dependenciesImagesFiles) downloadNetapi32DllFor(ctx context.Context, os os, arch arch) ([]imageFileDependency, error) {
	fail := func(err error) ([]imageFileDependency, error) {
		return nil, fmt.Errorf("cannot download netapi32.dll for %v/%v: %w", os, arch, err)
	}

	if os != osWindows {
		return nil, nil
	}

	targetFn := this.cacheLocationFor(os, arch, "netapi32.dll")

	err := this.getFileFromImage(ctx, os, arch, this.imageWithNetapi32Dll, "Files/Windows/System32/netapi32.dll", targetFn)
	if err != nil {
		return fail(err)
	}

	return []imageFileDependency{{os, arch, targetFn, netapi32DllFilename, 0644}}, nil
}

func (this *dependenciesImagesFiles) cacheLocationFor(os os, arch arch, base string) string {
	hash := sha1.Sum([]byte(base))
	return filepath.Join(this.cacheDirectory, os.String()+"-"+arch.String(), base58.Encode(hash[:]), "netapi32.dll")
}

func (this *dependenciesImagesFiles) getFileFromImage(ctx context.Context, os os, arch arch, imgName string, sourceFn, targetFn string) (rErr error) {
	fail := func(err error) error {
		return fmt.Errorf("cannot download %q from %q (%v/%v): %w", sourceFn, imgName, os, arch, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if !this.alwaysRefresh {
		efi, err := gos.Stat(targetFn)
		if err == nil {
			if efi.IsDir() {
				return failf("%s is a directory", targetFn)
			}
			return nil
		}
		if !sys.IsNotExist(err) {
			return fail(err)
		}
	}

	start := time.Now()
	l := log.With("image", imgName).
		With("os", os).
		With("arch", arch).
		With("file", sourceFn)

	l.Debug("download dependency file...")

	_ = gos.MkdirAll(filepath.Dir(targetFn), 0755)

	img, err := crane.Pull(imgName,
		crane.WithPlatform(&v1.Platform{
			OS:           os.String(),
			Architecture: arch.ociString(),
		}),
		crane.WithContext(ctx),
	)
	if err != nil {
		return failf("cannot pull image %q: %w", imgName, err)
	}

	layers, err := img.Layers()
	if err != nil {
		return failf("cannot get layers of image %q: %w", imgName, err)
	}

	for i, layer := range layers {
		ok, err := this.getFileFromLayer(layer, sourceFn, targetFn)
		if err != nil {
			return failf("layer %d", i, err)
		}
		if ok {
			l = l.With("duration", time.Since(start).Truncate(time.Millisecond))

			if l.IsDebugEnabled() {
				l.Info("download dependency file... DONE!")
			} else {
				l.Info("dependency file downloaded")
			}

			return nil
		}
	}

	return failf("file does not exist in image")
}

func (this *dependenciesImagesFiles) getFileFromLayer(layer v1.Layer, sourceFn, targetFn string) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, err
	}
	failf := func(msg string, args ...any) (bool, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	mt, err := layer.MediaType()
	if err != nil {
		return failf("cannot media type of layer: %w", err)
	}

	switch mt {
	case types.OCILayer, types.OCILayerZStd, types.OCIUncompressedLayer, types.DockerLayer, types.DockerForeignLayer, types.DockerUncompressedLayer:
	default:
		return false, nil
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return failf("cannot get uncompressed part of layer: %w", err)
	}
	defer common.IgnoreCloseError(r)

	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return failf("cannot read TAR from uncompressed part of layer: %w", err)
		}
		if strings.EqualFold(header.Name, sourceFn) {
			to, err := gos.OpenFile(targetFn, gos.O_TRUNC|gos.O_CREATE|gos.O_WRONLY, 0644)
			if err != nil {
				return failf("cannot create file %q: %w", targetFn, err)
			}
			defer common.KeepCloseError(&rErr, to)

			if _, err := io.Copy(to, tr); err != nil {
				return failf("cannot write file from archive %q to %q: %w", targetFn, err)
			}

			return true, nil
		}
	}

	return false, nil
}

type imageFileDependency struct {
	os     os
	arch   arch
	source string
	target string
	mode   gos.FileMode
}
