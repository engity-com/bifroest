package main

import (
	"context"
	"fmt"
	"io"
	gos "os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"
	"github.com/mattn/go-zglob"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
)

func newBuildArchive(b *build) *buildArchive {
	return &buildArchive{
		build: b,

		includedResources: []string{
			"README.md",
			"LICENSE",
			"SECURITY.md",
			"contrib/**/*",
		},
	}
}

type buildArchive struct {
	*build

	includedResources []string
}

func (this *buildArchive) attach(cmd *kingpin.CmdClause) {
	cmd.Flag("includedResource", "").
		PlaceHolder("<file>[,...]").
		StringsVar(&this.includedResources)
}

func (this *buildArchive) create(ctx context.Context, binary *buildArtifact) (_ *buildArtifact, rErr error) {
	format := bib.ArchiveFormatFor(binary.Platform.Os)
	fn := binary.Platform.FilenamePrefix(this.prefix) + format.Ext()

	success := false
	a, err := this.build.newBuildFileArtifact(ctx, binary.Platform, buildArtifactTypeArchive, fn)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)

	fail := func(err error) (*buildArtifact, error) {
		return nil, fmt.Errorf("cannot create %v: %w", a, err)
	}

	l := log.With("platform", a.Platform).
		With("stage", buildStageArchive)

	start := time.Now()
	l.Debug("building archive...")

	f, err := gos.OpenFile(a.filepath, gos.O_TRUNC|gos.O_CREATE|gos.O_WRONLY, 0644)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, f)

	baw, err := this.newWriter(binary, f)
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, baw)

	if err := baw.addFile(binary.Platform.Os.AppendExtToFilename(this.prefix), binary.filepath, 0755); err != nil {
		return fail(err)
	}
	for _, res := range this.includedResources {
		if err := this.addResource(res, baw); err != nil {
			return fail(err)
		}
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building archive... DONE!")
	} else {
		ld.Info("archive built")
	}

	success = true
	return a, nil
}

func (this *buildArchive) addResource(src string, to buildArchiveWriter) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot add resource %q: %w", src, err)
	}
	candidates, err := zglob.Glob(src)
	if err != nil {
		return fail(err)
	}

	for _, candidate := range candidates {
		fi, err := gos.Stat(candidate)
		if err != nil {
			return fail(err)
		}
		if !fi.IsDir() {
			if err := to.addFile(candidate, candidate, fi.Mode()); err != nil {
				return fail(err)
			}
		}
	}

	return nil
}

func (this *buildArchive) newWriter(binary *buildArtifact, w io.Writer) (buildArchiveWriter, error) {
	format := bib.ArchiveFormatFor(binary.Platform.Os)
	switch format {
	case bib.ArchiveFormatTgz:
		return this.newTgzWriter(binary.time, w)
	case bib.ArchiveFormatZip:
		return this.newZipWriter(binary.time, w)
	default:
		return nil, fmt.Errorf("unknown archive format: %v", format)
	}
}

type buildArchiveWriter interface {
	io.Closer
	addFile(name, sourceFn string, mode gos.FileMode) error
}
