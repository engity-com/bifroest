package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"

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
		platform: &platform{
			testing: as[0].testing,
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

	for _, a := range as {
		if a.t.canBePublished() && a.filepath != "" {
			sf, err := a.openFile()
			if err != nil {
				return fail(err)
			}

			hash := sha256.New()
			if _, err := io.Copy(hash, sf); err != nil {
				return fail(err)
			}

			if _, err := fmt.Fprintf(f, "%x %s\n", hash.Sum(nil), filepath.Base(a.filepath)); err != nil {
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
