package main

import (
	"context"
	"fmt"
	gos "os"
	osexec "os/exec"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/binary"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

func newBuildBinary(b *build) *buildBinary {
	return &buildBinary{
		build: b,
	}
}

type buildBinary struct {
	*build

	darwinSigningIdentity string
}

func (this *buildBinary) attach(cmd *kingpin.CmdClause) {
	cmd.Flag("darwinSigningIdentity", "Developer ID Application identity used to sign native Darwin binaries.").
		Envar("BIFROEST_DARWIN_SIGNING_IDENTITY").
		PlaceHolder("<identity>").
		StringVar(&this.darwinSigningIdentity)
}

func (this *buildBinary) compile(ctx context.Context, p *bib.Platform) (*buildArtifact, *buildArtifact, error) {
	fail := func(err error) (*buildArtifact, *buildArtifact, error) {
		return nil, nil, fmt.Errorf("cannot build %v: %w", *p, err)
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
	if p.Os == sys.OsWindows {
		if err := this.addWindowsResources(a); err != nil {
			return fail(err)
		}
	}
	notice, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeNotice, p.FilenamePrefix(this.prefix)+".third-party-notices.txt")
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, notice)
	if err := this.createThirdPartyNotices(ctx, req, a, notice.filepath); err != nil {
		return fail(err)
	}
	a.thirdPartyNoticesFilepath = notice.filepath
	if err := this.signDarwin(ctx, a); err != nil {
		return fail(err)
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building binary... DONE!")
	} else {
		ld.Info("binary built")
	}

	success = true
	return a, notice, nil
}

func (this *buildBinary) signDarwin(ctx context.Context, artifact *buildArtifact) error {
	if artifact.Os != sys.OsDarwin || this.darwinSigningIdentity == "" {
		return nil
	}
	commands := [][]string{
		{"--force", "--sign", this.darwinSigningIdentity, "--options", "runtime", "--timestamp", artifact.filepath},
		{"--verify", "--strict", "--verbose=2", artifact.filepath},
	}
	for _, args := range commands {
		command := osexec.CommandContext(ctx, "codesign", args...)
		command.Env = gos.Environ()
		output, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("codesign %s failed: %w: %s", args[0], err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}
