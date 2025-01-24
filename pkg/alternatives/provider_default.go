//go:build !local_build

package alternatives

import (
	"context"
	"io"
	"net/http"
	"net/url"
	goos "os"
	"path/filepath"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

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
		l.Debug("requested binaries matches current binary; returning itself")
		return result, nil
	}

	fn, err := this.alternativesLocationFor(hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	if fn == "" {
		l.Debug("alternatives location resolves to empty")
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
		l.Warn("existing broken alternatives' location exists and has been deleted")
	} else {
		l.Debug("existing alternatives location was returned")
		return fn, nil
	}

	du, err := this.alternativesDownloadUrlFor(hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	if du == nil {
		l.Debug("no existing alternative location and download url resolves to empty")
		return "", nil
	}

	l = l.With("url", du)

	l.Info("there is no existing alternative; downloading it...")

	req, err := http.NewRequest(http.MethodGet, du.String(), nil)
	if err != nil {
		return fail(err)
	}
	req = req.WithContext(ctx)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return failf(errors.System, "cannot download alternative from %v: %w", du, err)
	}
	if resp.StatusCode != http.StatusOK {
		return failf(errors.System, "cannot download alternative from %v: expected status code %d; but got: %d", du, http.StatusOK, resp.StatusCode)
	}
	defer common.IgnoreCloseError(resp.Body)

	if err := goos.MkdirAll(filepath.Dir(fn), 0755); err != nil {
		return failf(errors.System, "cannot create directory to store alternative %v inside: %w", fn, err)
	}

	out, err := goos.OpenFile(fn, goos.O_CREATE|goos.O_TRUNC|goos.O_WRONLY, 0644)
	if err != nil {
		return failf(errors.System, "cannot create target file %q to store alternative inside: %w", fn, err)
	}
	defer common.KeepCloseError(&rErr, out)

	if _, err := io.Copy(out, resp.Body); err != nil {
		return failf(errors.System, "cannot store %q into target file %q to store alternative inside: %w", du, fn, err)
	}

	l.Info("there is no existing alternative; downloading it... DONE!")

	return fn, nil
}

func (this *provider) FindOciImageFor(_ context.Context, _ sys.Os, _ sys.Arch) (string, error) {
	ver := this.version.Version()
	ver = strings.TrimPrefix(ver, "v")
	return "ghcr.io/engity-com/bifroest:generic-" + ver, nil
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
		return failf(errors.Config, "cannot resolve alternative location: %w", err)
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
		return failf(errors.Config, "cannot resolve alternative download url: %w", err)
	}
	return result, nil
}
