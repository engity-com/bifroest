package images

import (
	"context"
	"embed"
	_ "embed"
	"io/fs"
	"iter"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	ImageMinimal = "minimal"
	ImageScratch = "scratch"

	fromMinimalLinux   = "alpine"
	fromMinimalWindows = "mcr.microsoft.com/windows/nanoserver:ltsc2022"
)

var (
	//go:embed contrib
	contrib embed.FS
)

func NewBuilder() (*Builder, error) {
	return &Builder{}, nil
}

type Builder struct {
}

type BuildRequest struct {
	From string
	Os   sys.Os
	Arch sys.Arch
	Time time.Time

	Env          sys.EnvVars
	EntryPoint   []string
	Cmd          []string
	ExposedPorts map[string]struct{}
	Annotations  map[string]string

	Contents               iter.Seq2[LayerItem, error]
	BifroestBinarySource   string
	BifroestBinarySourceFs fs.FS
	AddDummyConfiguration  bool
	AddSkeletonStructure   bool
}

func (this BuildRequest) ToOciPlatform() (*v1.Platform, error) {
	return v1.ParsePlatform(this.Os.String() + "/" + this.Arch.Oci())
}

func (this *Builder) Build(ctx context.Context, req BuildRequest) (Image, error) {
	fail := func(err error) (Image, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (Image, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	success := false

	var result image

	platform, err := req.ToOciPlatform()
	if err != nil {
		return fail(err)
	}

	if strings.EqualFold(req.From, ImageMinimal) {
		switch req.Os {
		case sys.OsWindows:
			req.From = fromMinimalWindows
		case sys.OsLinux:
			req.From = fromMinimalLinux
		default:
			return failf("unsupported operating system: %v", req.Os)
		}
	}

	var img v1.Image
	if strings.EqualFold(req.From, ImageScratch) {
		img = empty.Image
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	} else {
		if img, err = crane.Pull(req.From,
			crane.WithPlatform(platform),
			crane.WithContext(ctx),
		); err != nil {
			return fail(err)
		}
	}

	cfg, err := img.ConfigFile()
	if err != nil {
		return fail(err)
	}
	cfg = cfg.DeepCopy()
	cfg.Architecture = platform.Architecture
	cfg.OS = platform.OS
	cfg.OSVersion = platform.OSVersion
	cfg.OSFeatures = platform.OSFeatures
	cfg.Variant = platform.Variant
	cfg.Config.Labels = make(map[string]string)
	if v := req.ExposedPorts; v != nil {
		cfg.Config.ExposedPorts = v
	} else {
		cfg.Config.ExposedPorts = make(map[string]struct{})
	}
	if v := req.EntryPoint; len(v) > 0 {
		cfg.Config.Entrypoint = v
	}
	if v := req.Cmd; len(v) > 0 {
		cfg.Config.Cmd = v
	}
	cfg.Config.Env = req.Env.Strings()
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		return fail(err)
	}

	annotations := req.Annotations
	if annotations == nil {
		annotations = make(map[string]string)
	}
	img = mutate.Annotations(img, annotations).(v1.Image)

	contents, err := this.collectBaseContents(req)
	if err != nil {
		return fail(err)
	}

	if v := req.Contents; v != nil {
		contents = common.JoinSeq2[LayerItem, error](v, contents)
	}

	if contents != nil {
		bufferedLayer, err := NewTarLayer(contents, LayerOpts{
			Os:   req.Os,
			Id:   req.Os.String() + "-" + req.Arch.String(),
			Time: req.Time,
		})
		if err != nil {
			return fail(err)
		}
		defer common.IgnoreCloseErrorIfFalse(&success, bufferedLayer)

		if img, err = mutate.AppendLayers(img, bufferedLayer.Layer); err != nil {
			return fail(err)
		}

		result.closers = append(result.closers, bufferedLayer)
	}

	result.Image = img
	success = true
	return &result, nil
}

func (this *Builder) collectBaseContents(req BuildRequest) (iter.Seq2[LayerItem, error], error) {
	fail := func(err error) (iter.Seq2[LayerItem, error], error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (iter.Seq2[LayerItem, error], error) {
		return fail(errors.System.Newf(msg, args...))
	}

	var result []LayerItem

	if req.AddDummyConfiguration {
		v := LayerItem{
			SourceFs: contrib,
			Mode:     0644,
		}

		switch req.Os {
		case sys.OsWindows:
			v.TargetFile = `C:\ProgramData\Engity\Bifroest\configuration.yaml`
			v.SourceFile = "contrib/configuration-windows.yaml"
		case sys.OsLinux:
			v.TargetFile = `/etc/engity/bifroest/configuration.yaml`
			if strings.EqualFold(req.From, ImageScratch) {
				v.SourceFile = "contrib/configuration-unix.yaml"
			} else {
				v.SourceFile = "contrib/configuration-unix-extended.yaml"
			}
		default:
			return failf("cannot add dummy configuration for os %v", req.Os)
		}

		result = append(result, v)
	}

	if req.AddSkeletonStructure {
		switch req.Os {
		case sys.OsLinux:
			if strings.EqualFold(req.From, ImageScratch) {
				result = append(result, LayerItem{
					SourceFs:   contrib,
					SourceFile: "contrib/passwd",
					TargetFile: "/etc/passwd",
					Mode:       0644,
				}, LayerItem{
					SourceFs:   contrib,
					SourceFile: "contrib/group",
					TargetFile: "/etc/group",
					Mode:       0644,
				}, LayerItem{
					SourceFs:   contrib,
					SourceFile: "contrib/shadow",
					TargetFile: "/etc/shadow",
					Mode:       0600,
				})
			}
		case sys.OsWindows:
			// ignore
		default:
			return failf("cannot add dummy configuration for os %v", req.Os)
		}
	}

	if v := req.BifroestBinarySource; v != "" {
		item := LayerItem{
			SourceFs:   req.BifroestBinarySourceFs,
			SourceFile: v,
			TargetFile: sys.BifroestBinaryLocation(req.Os),
			Mode:       0755,
		}

		if len(item.TargetFile) == 0 {
			return failf("cannot resolve Bifröest binary for os %v", req.Os)
		}

		result = append(result, item)
	}

	if len(result) == 0 {
		return nil, nil
	}

	return common.Seq2ErrOf[LayerItem](result...), nil
}
