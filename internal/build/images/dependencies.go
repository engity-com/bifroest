package images

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

	log "github.com/echocat/slf4g"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/mr-tron/base58"

	"github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	DefaultDependenciesCacheDirectory = filepath.Join(".cache", "dependencies", "images")
)

type Dependencies struct {
	CacheDirectory       string
	AlwaysRefresh        bool
	ImageWithNetapi32Dll string
}

type FetchDependenciesRequest struct {
	Os   sys.Os
	Arch sys.Arch

	CacheDirectory       string
	AlwaysRefresh        bool
	ImageWithNetapi32Dll string
}

func FetchDependencies(ctx context.Context, req FetchDependenciesRequest) (result FileDependencies, err error) {
	v, err := downloadNetapi32DllFor(ctx, req)
	if err != nil {
		return nil, err
	}
	result = append(result, v...)

	return result, nil
}

func dependenciesCacheLocationFor(req FetchDependenciesRequest, base string) string {
	hash := sha1.Sum([]byte(base))
	return filepath.Join(req.cacheDirectory(), req.os().String()+"-"+req.arch().String(), base58.Encode(hash[:]), "netapi32.dll")
}

func getFileFromImage(ctx context.Context, req FetchDependenciesRequest, imgName string, sourceFn, targetFn string) (rErr error) {
	os := req.os()
	arch := req.arch()
	fail := func(err error) error {
		return fmt.Errorf("cannot download %q from %q (%v/%v): %w", sourceFn, imgName, os, arch, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if !req.alwaysRefresh() {
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
			Architecture: arch.Oci(),
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
		ok, err := getFileFromLayer(layer, sourceFn, targetFn)
		if err != nil {
			return failf("layer %d: %w", i, err)
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

func getFileFromLayer(layer v1.Layer, sourceFn, targetFn string) (_ bool, rErr error) {
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
			//goland:noinspection GoDeferInLoop
			defer common.KeepCloseError(&rErr, to)

			if _, err := io.Copy(to, tr); err != nil {
				return failf("cannot write file from archive %q: %w", targetFn, err)
			}

			return true, nil
		}
	}

	return false, nil
}

func (this FetchDependenciesRequest) os() sys.Os {
	if v := this.Os; !v.IsZero() {
		return v
	}
	return build.Goos
}

func (this FetchDependenciesRequest) arch() sys.Arch {
	if v := this.Arch; !v.IsZero() {
		return v
	}
	return build.Goarch
}

func (this FetchDependenciesRequest) cacheDirectory() string {
	if v := this.CacheDirectory; v != "" {
		return v
	}
	return DefaultDependenciesCacheDirectory
}

func (this FetchDependenciesRequest) alwaysRefresh() bool {
	return this.AlwaysRefresh
}

type FileDependency struct {
	Os     sys.Os
	Arch   sys.Arch
	Source string
	Target string
	Mode   gos.FileMode
}

func (this FileDependency) ToLayerItem() LayerItem {
	return LayerItem{
		SourceFile: this.Source,
		TargetFile: this.Target,
		Mode:       this.Mode,
	}
}

type FileDependencies []FileDependency

func (this FileDependencies) ToLayerItems() []LayerItem {
	result := make([]LayerItem, len(this))
	for i, v := range this {
		result[i] = v.ToLayerItem()
	}
	return result
}
