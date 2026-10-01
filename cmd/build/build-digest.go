package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
)

func newBuildDigest(b *build) *buildDigest {
	return &buildDigest{
		build: b,
	}
}

type buildDigest struct {
	*build
}

func (this *buildDigest) attach(_ *kingpin.CmdClause) {}

func (this *buildDigest) create(_ context.Context, as buildArtifacts) (_ buildArtifacts, rErr error) {
	if len(as) == 0 {
		return as, nil
	}

	success := false
	result := &buildArtifact{
		Platform: &bib.Platform{
			Testing: as[0].Testing,
		},
		buildContext: as[0].buildContext,
		t:            buildArtifactTypeDigest,
		filepath:     as[0].buildContext.filepath("bifroest-checksums.txt"),
	}
	defer common.IgnoreCloseErrorIfFalse(&success, result)

	fail := func(err error) (buildArtifacts, error) {
		return nil, fmt.Errorf("cannot create digest %v: %w", result, err)
	}

	l := log.With("stage", buildStageDigest)

	start := time.Now()
	l.Debug("building digest...")

	f, err := result.createFile()
	if err != nil {
		return fail(err)
	}
	defer common.KeepCloseError(&rErr, f)

	candidates := slices.Collect(as.filter(func(candidate *buildArtifact) bool {
		return candidate.t.canBePublished() && candidate.filepath != ""
	}))
	slices.SortFunc(candidates, func(a, b *buildArtifact) int {
		return strings.Compare(a.name(), b.name())
	})
	for _, a := range candidates {
		if a.t.canBePublished() && a.filepath != "" {
			digest, err := sha256File(a.filepath)
			if err != nil {
				return fail(err)
			}
			if _, err := fmt.Fprintf(f, "%s  %s\n", strings.TrimPrefix(digest, "sha256:"), filepath.Base(a.filepath)); err != nil {
				return fail(err)
			}
		}
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building digest... DONE!")
	} else {
		ld.Info("digest built")
	}

	success = true
	return append(as, result), nil
}
