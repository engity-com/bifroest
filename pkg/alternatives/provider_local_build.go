//go:build local_build

package alternatives

import (
	"context"
	"crypto/sha256"
	"io"
	goos "os"
	"path/filepath"

	"github.com/docker/docker/errdefs"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/mr-tron/base58"

	"github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/binary"
	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/debug"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	AnnotationSourceBinaryHash = "org.engity.bifroest/source-binary-hash"
)

var (
	thisBinaryHash = func() string {
		fn, err := goos.Executable()
		if err != nil {
			panic(errors.System.Newf("cannot resolve own executable location: %w", err))
		}

		result, err := createHashOfFile(fn)
		if err != nil {
			panic(err)
		}

		return result
	}()
)

func (this *provider) FindBinaryFor(ctx context.Context, hostOs sys.Os, hostArch sys.Arch) (_ string, rErr error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(msg string, args ...any) (string, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	l := this.logger().
		With("os", hostOs).
		With("arch", hostArch).
		With("version", this.version.Version())

	result := filepath.Join("var", "dist", "local-development",
		hostOs.AppendExtToFilename("bifroest-"+hostOs.String()+"-"+hostArch.String()+"-generic"),
	)
	sourceHashFn := result + ".sourceHash"

	l = l.With("location", result)

	fi, err := goos.Stat(result)
	if sys.IsNotExist(err) {
		// Ok... just continue...
	} else if err != nil {
		return failf("cannot check for existent cached binary %q: %w", result, err)
	} else if !fi.IsDir() {
		sourceHashB, err := goos.ReadFile(sourceHashFn)
		if sys.IsNotExist(err) {
			// Ok... just continue...
		} else if err != nil {
			return failf("cannot check for existent cached binary source hash %q: %w", sourceHashB, err)
		}
		// Ok the current source hash and the hash of this binary is the same. We can just use it...
		if string(sourceHashB) == thisBinaryHash {
			l.Debug("existing imp alternatives location was returned")
			return result, nil
		}
	}

	if !build.IsOsAndArchSupported(hostOs, hostArch) {
		l.Debug("imp alternatives location resolves to empty (because build of target is not supported)")
		return "", nil
	}

	req := binary.BuildRequest{
		Platform: build.Platform{
			Os:      hostOs,
			Arch:    hostArch,
			Edition: sys.EditionGeneric,
			Testing: true,
		},
		Version:    "local-development",
		TargetFile: result,
		Tags:       debug.GetTargetBuildTags(),
	}

	l.Info("there is no alternative existing; building it...")

	if err := binary.Build(ctx, req); err != nil {
		return fail(err)
	}

	if err := goos.WriteFile(sourceHashFn, []byte(thisBinaryHash), 0644); err != nil {
		return fail(err)
	}

	l.Info("there is no alternative existing; building it... DONE!")

	return result, nil
}

func (this *provider) FindOciImageFor(ctx context.Context, os sys.Os, arch sys.Arch) (_ string, rErr error) {
	fail := func(err error) (string, error) {
		return "", errors.System.Newf("cannot find oci image for %v/%v: %w", os, arch, err)
	}
	failf := func(msg string, args ...any) (string, error) {
		return fail(errors.System.Newf(msg, args...))
	}
	version := this.version.Version()

	tag, err := name.NewTag("local/bifroest:generic-" + version)
	if err != nil {
		return fail(err)
	}

	l := this.logger().
		With("os", os).
		With("arch", arch).
		With("version", this.version.Version())

	// Check for existing image...
	existing, err := daemon.Image(tag, daemon.WithContext(ctx))
	if errdefs.IsNotFound(err) {
		// Just continue...
	} else if err != nil {
		return fail(err)
	} else if existing != nil {
		// If it does exist ensure the containing hash of the binary is the same, otherwise we'll rebuild...
		config, err := existing.ConfigFile()
		if err == nil &&
			config.Config.Labels != nil &&
			config.Config.Labels[AnnotationSourceBinaryHash] == thisBinaryHash {
			l.Debug("existing alternative oci image was returned")
			return tag.String(), nil
		}
	}

	l.Info("building new alternative oci image...")

	sourceBinaryLocation, err := this.FindBinaryFor(ctx, os, arch)
	if err != nil {
		return fail(err)
	}

	targetBinaryFileLocation := sys.BifroestBinaryFileLocation(os)
	if len(targetBinaryFileLocation) == 0 {
		return failf("cannot resolve Bifröst's binary file location for os %v", os)
	}
	targetBinaryDirLocation := sys.BifroestBinaryDirLocation(os)
	if len(targetBinaryDirLocation) == 0 {
		return failf("cannot resolve Bifröst's binary dir location for os %v", os)
	}

	img, err := images.Build(ctx, images.BuildRequest{
		From:                 images.ImageMinimal,
		Os:                   os,
		Arch:                 arch,
		BifroestBinarySource: sourceBinaryLocation,
		PathEnv:              []string{targetBinaryDirLocation},
		EntryPoint:           []string{targetBinaryFileLocation},
		Cmd:                  []string{},
		ExposedPorts: map[string]struct{}{
			"22/tcp": {},
		},
		AddDummyConfiguration: true,
		AddSkeletonStructure:  true,
		Labels: map[string]string{
			AnnotationSourceBinaryHash: thisBinaryHash,
		},
	})
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, img)

	if _, err := daemon.Write(tag, img, daemon.WithContext(ctx)); err != nil {
		return fail(err)
	}

	l.Info("building new alternative oci image... DONE!")

	return tag.String(), nil
}

func createHashOfFile(fn string) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.System.Newf("cannot create hash of file %q: %w", fn, err)
	}

	f, err := goos.Open(fn)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseError(f)

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fail(err)
	}

	return base58.Encode(h.Sum(nil)), nil
}
