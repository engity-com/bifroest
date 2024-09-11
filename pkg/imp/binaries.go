package imp

import (
	"context"
	"io"
	"net/http"
	"net/url"
	goos "os"
	"path/filepath"
	"runtime"

	log "github.com/echocat/slf4g"
	"github.com/kardianos/osext"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type BinaryProvider interface {
	FindBinaryFor(ctx context.Context, os, arch string) (string, error)
}

func NewBinaries(_ context.Context, version common.Version, conf *configuration.Imp) (*Binaries, error) {
	return &Binaries{
		conf:    conf,
		version: version,
	}, nil
}

type Binaries struct {
	conf    *configuration.Imp
	version common.Version

	Logger log.Logger
}

func (this *Binaries) FindBinaryFor(ctx context.Context, os, arch string) (_ string, rErr error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(t errors.Type, msg string, args ...any) (string, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	l := this.logger().
		With("os", os).
		With("arch", arch).
		With("version", this.version.Version())

	if sys.IsBinaryCompatibleWithHost(runtime.GOOS, os, runtime.GOARCH, arch) {
		result, err := osext.Executable()
		if err != nil {
			return failf(errors.System, "cannot resolve the location of the server's executable location: %w", err)
		}
		l.Debug("requested imp binaries does match current binary; returning itself")
		return result, nil
	}

	fn, err := this.alternativesLocationFor(os, arch)
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

	du, err := this.alternativesDownloadUrlFor(os, arch)
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

func (this *Binaries) alternativesLocationFor(os, arch string) (string, error) {
	fail := func(err error) (string, error) {
		return "", err
	}
	failf := func(t errors.Type, msg string, args ...any) (string, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ctx := alternativeResolutionContext{os, arch, this.version.Version()}
	result, err := this.conf.AlternativesLocation.Render(ctx)
	if err != nil {
		return failf(errors.Config, "cannot resolve imp alternative location: %w", err)
	}
	return result, nil
}

func (this *Binaries) alternativesDownloadUrlFor(os, arch string) (*url.URL, error) {
	fail := func(err error) (*url.URL, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (*url.URL, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	ctx := alternativeResolutionContext{os, arch, this.version.Version()}
	result, err := this.conf.AlternativesDownloadUrl.Render(ctx)
	if err != nil {
		return failf(errors.Config, "cannot resolve imp alternative download url: %w", err)
	}
	return result, nil
}

func (this *Binaries) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("imp.binaries")
}

func (this *Binaries) Close() error {
	return nil
}

type alternativeResolutionContext struct {
	Os           string
	Architecture string
	Version      string
}

func (this alternativeResolutionContext) Ext() string {
	switch this.Os {
	case "windows":
		return ".exe"
	default:
		return ""
	}
}
