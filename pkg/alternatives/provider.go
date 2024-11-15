package alternatives

import (
	"context"
	"io"
	"net/http"
	"net/url"
	goos "os"
	"path/filepath"

	"github.com/docker/docker/errdefs"
	log "github.com/echocat/slf4g"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/oci/images"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Provider interface {
	io.Closer
	FindBinaryFor(ctx context.Context, os sys.Os, arch sys.Arch) (string, error)
	FindOciImageFor(ctx context.Context, os sys.Os, arch sys.Arch, opts FindOciImageOpts) (string, error)
}

type FindOciImageOpts struct {
	Local bool
	Force bool
}

func NewProvider(_ context.Context, version sys.Version, conf *configuration.Alternatives) (Provider, error) {
	ib, err := images.NewBuilder()
	if err != nil {
		return nil, err
	}
	return &provider{
		conf:          conf,
		version:       version,
		imagesBuilder: ib,
	}, nil
}

type provider struct {
	conf          *configuration.Alternatives
	version       sys.Version
	imagesBuilder *images.Builder

	Logger log.Logger
}

func (this *provider) FindBinaryFor(ctx context.Context, hostOs sys.Os, hostArch sys.Arch) (_ string, rErr error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(t errors.Type, msg string, args ...any) (string, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	l := this.logger().
		With("os", hostOs).
		With("arch", hostArch).
		With("version", this.version.Version())

	if sys.IsBinaryCompatibleWithHost(this.version.Os(), this.version.Arch(), hostOs, hostArch) {
		result, err := goos.Executable()
		if err != nil {
			return failf(errors.System, "cannot resolve the location of the server's executable location: %w", err)
		}
		l.Debug("requested imp binaries does match current binary; returning itself")
		return result, nil
	}

	fn, err := this.alternativesLocationFor(hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	if fn == "" {
		l.Debug("imp alternatives location resolves to empty")
		return "", nil
	}
	l = l.With("location", fn)

	i, err := goos.Stat(fn)
	if sys.IsNotExist(err) {
		// Ok, lets try to download it...
	} else if err != nil {
		return failf(errors.System, "cannot load information of alternative location file %q: %w", fn, err)
	} else if i.IsDir() || i.Size() == 0 {
		if err := goos.RemoveAll(fn); err != nil {
			return failf(errors.System, "cannot remove old alternative location file %q: %w", fn, err)
		}
		l.Warn("existing imp alternatives location which is broken exists and was deleted")
	} else {
		l.Debug("existing imp alternatives location was returned")
		return fn, nil
	}

	du, err := this.alternativesDownloadUrlFor(hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	if du == nil {
		l.Debug("there does no existing imp alternatives exists at location and the download url resolves to empty")
		return "", nil
	}

	l = l.With("url", du)

	l.Info("there is no existing imp alternative existing; downloading it...")

	req, err := http.NewRequest(http.MethodGet, du.String(), nil)
	if err != nil {
		return fail(err)
	}
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return failf(errors.System, "cannot download imp alternative from %v: %w", du, err)
	}
	if resp.StatusCode != http.StatusOK {
		return failf(errors.System, "cannot download imp alternative from %v: expected status code %d; but got: %d", du, http.StatusOK, resp.StatusCode)
	}
	defer common.IgnoreCloseError(resp.Body)

	if err := goos.MkdirAll(filepath.Dir(fn), 0755); err != nil {
		return failf(errors.System, "cannot create directory to store imp alternative %v inside: %w", fn, err)
	}

	out, err := goos.OpenFile(fn, goos.O_CREATE|goos.O_TRUNC|goos.O_WRONLY, 0644)
	if err != nil {
		return failf(errors.System, "cannot create target file %q to store imp alternative inside: %w", fn, err)
	}
	defer common.KeepCloseError(&rErr, out)

	if _, err := io.Copy(out, resp.Body); err != nil {
		return failf(errors.System, "cannot store %q into target file %q to store imp alternative inside: %w", du, fn, err)
	}

	l.Info("there is no existing imp alternative existing; downloading it... DONE!")

	return fn, nil
}

func (this *provider) FindOciImageFor(ctx context.Context, os sys.Os, arch sys.Arch, opts FindOciImageOpts) (_ string, rErr error) {
	fail := func(err error) (string, error) {
		return "", errors.System.Newf("cannot find oci image for %v/%v: %w", os, arch, err)
	}
	failf := func(msg string, args ...any) (string, error) {
		return fail(errors.System.Newf(msg, args...))
	}
	version := this.version.Version()

	if !opts.Local {
		return "ghcr.io/engity-com/bifroest:generic-" + version, nil
	}

	tag, err := name.NewTag("local/bifroest:generic-" + version)
	if err != nil {
		return fail(err)
	}

	if !opts.Force {
		if _, err := daemon.Image(tag, daemon.WithContext(ctx)); errdefs.IsNotFound(err) {
			// This is Ok, we'll continue to build it...
		} else if err != nil {
			return fail(err)
		} else {
			return tag.String(), nil
		}
	}

	sourceBinaryLocation, err := this.FindBinaryFor(ctx, os, arch)
	if err != nil {
		return fail(err)
	}

	targetBinaryLocation := sys.BifroestBinaryLocation(os)
	if len(targetBinaryLocation) == 0 {
		return failf("cannot resolve Bifröst's binary location for os %v", os)
	}

	img, err := this.imagesBuilder.Build(ctx, images.BuildRequest{
		From:                 images.ImageMinimal,
		Os:                   os,
		Arch:                 arch,
		BifroestBinarySource: sourceBinaryLocation,
		EntryPoint:           []string{targetBinaryLocation},
		Cmd:                  []string{},
		ExposedPorts: map[string]struct{}{
			"22/tcp": {},
		},
		AddDummyConfiguration: true,
		AddSkeletonStructure:  true,
	})
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, img)

	if _, err := daemon.Write(tag, img, daemon.WithContext(ctx)); err != nil {
		return fail(err)
	}

	return tag.String(), nil
}

func (this *provider) alternativesLocationFor(os sys.Os, arch sys.Arch) (string, error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(t errors.Type, msg string, args ...any) (string, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ctx := alternativeResolutionContext{os, arch, this.version.Version()}
	result, err := this.conf.Location.Render(ctx)
	if err != nil {
		return failf(errors.Config, "cannot resolve imp alternative location: %w", err)
	}
	return result, nil
}

func (this *provider) alternativesDownloadUrlFor(os sys.Os, arch sys.Arch) (*url.URL, error) {
	fail := func(err error) (*url.URL, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (*url.URL, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ctx := alternativeResolutionContext{os, arch, this.version.Version()}
	result, err := this.conf.DownloadUrl.Render(ctx)
	if err != nil {
		return failf(errors.Config, "cannot resolve imp alternative download url: %w", err)
	}
	return result, nil
}

func (this *provider) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("imp.binaries")
}

func (this *provider) Close() error {
	return nil
}

type alternativeResolutionContext struct {
	os      sys.Os
	arch    sys.Arch
	version string
}

func (this alternativeResolutionContext) Ext() string {
	switch this.os {
	case sys.OsWindows:
		return ".exe"
	default:
		return ""
	}
}
func (this alternativeResolutionContext) PackageExt() string {
	switch this.os {
	case sys.OsWindows:
		return ".zip"
	default:
		return ".tgz"
	}
}

func (this alternativeResolutionContext) GetField(name string) (any, bool, error) {
	switch name {
	case "os":
		return this.os, true, nil
	case "architecture", "arch":
		return this.arch, true, nil
	case "version":
		return this.version, true, nil
	case "edition":
		return "generic", true, nil
	case "ext":
		return this.Ext(), true, nil
	case "packageExt":
		return this.PackageExt(), true, nil
	default:
		return nil, false, nil
	}
}
