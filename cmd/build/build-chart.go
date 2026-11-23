package main

import (
	"context"
	"fmt"
	gos "os"

	"github.com/Masterminds/semver/v3"
	"github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/charts"
)

type buildChart struct {
	*build
	source string
}

func newBuildChart(b *build) *buildChart {
	return &buildChart{build: b, source: "charts/bifroest"}
}

func (this *buildChart) create(ctx context.Context, forTesting bool) (*buildArtifact, error) {
	bc, err := this.getBuildContext(ctx)
	if err != nil {
		return nil, err
	}
	version := bc.version.String()
	if bc.version.semver != nil {
		version = bc.version.semver.String()
	}
	if _, err := semver.StrictNewVersion(version); err != nil {
		if this.rawStages.contains(buildStageChart) {
			return nil, fmt.Errorf("cannot build chart for non-semantic application version %q", version)
		}
		log.With("stage", buildStageChart).With("version", version).Info("chart skipped: application version is not semantic")
		return nil, nil
	}
	chart, err := charts.Build(ctx, gos.DirFS(this.source), version, bc.time)
	if err != nil {
		return nil, fmt.Errorf("cannot build chart: %w", err)
	}
	result := &buildArtifact{
		Platform:     &bib.Platform{Testing: forTesting},
		buildContext: bc,
		t:            buildArtifactTypeChart,
		filepath:     bc.filepath("bifroest-" + chart.Version + ".tgz"),
		ociImage:     chart.Image,
		chartVersion: chart.Version,
	}
	if err := gos.WriteFile(result.filepath, chart.Data, 0644); err != nil {
		return nil, fmt.Errorf("cannot write chart: %w", err)
	}
	log.With("stage", buildStageChart).With("version", chart.Version).Info("chart built")
	return result, nil
}
