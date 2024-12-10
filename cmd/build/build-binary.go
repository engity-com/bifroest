package main

import (
	"context"
	"fmt"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/binary"
	"github.com/engity-com/bifroest/pkg/common"
)

func newBuildBinary(b *build) *buildBinary {
	return &buildBinary{
		build: b,
	}
}

type buildBinary struct {
	*build
}

func (this *buildBinary) attach(_ *kingpin.CmdClause) {}

func (this *buildBinary) compile(ctx context.Context, p *bib.Platform) (*buildArtifact, error) {
	fail := func(err error) (*buildArtifact, error) {
		return nil, fmt.Errorf("cannot build %v: %w", *p, err)
	}

	assumedBuildOs := this.assumedBuildOs()
	assumedBuildArch := this.assumedBuildArch()
	if err := p.AssertBinarySupported(assumedBuildOs, assumedBuildArch); err != nil {
		return fail(err)
	}

	fn := p.Os.AppendExtToFilename(p.FilenamePrefix(this.prefix))

	success := false
	a, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeBinary, fn)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)

	l := log.With("platform", p).
		With("stage", buildStageBinary).
		With("file", a.filepath)

	req := binary.BuildRequest{
		Platform:             *a.Platform,
		Time:                 a.time,
		Version:              a.version.String(),
		Vendor:               a.vendor,
		Revision:             a.revision,
		TargetFile:           a.filepath,
		WslBuildDistribution: this.wslBuildDistribution,
		AssumedBuildOs:       assumedBuildOs,
		AssumedBuildArch:     assumedBuildArch,
	}

	start := time.Now()
	l.Debug("building binary...")

	if err := binary.Build(ctx, req); err != nil {
		return fail(err)
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building binary... DONE!")
	} else {
		ld.Info("binary built")
	}

	success = true
	return a, nil
}
