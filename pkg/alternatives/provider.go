package alternatives

import (
	"context"
	"io"

	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

type Provider interface {
	io.Closer
	FindBinaryFor(ctx context.Context, os sys.Os, arch sys.Arch) (string, error)
	FindOciImageFor(ctx context.Context, os sys.Os, arch sys.Arch) (string, error)
}

func NewProvider(_ context.Context, version sys.Version, conf *configuration.Alternatives) (Provider, error) {
	return &provider{
		conf:    conf,
		version: version,
	}, nil
}

type provider struct {
	conf    *configuration.Alternatives
	version sys.Version

	Logger log.Logger
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
