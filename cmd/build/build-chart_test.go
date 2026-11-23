package main

import (
	"encoding/json"
	gos "os"
	"path/filepath"
	"slices"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/charts"
	"github.com/engity-com/bifroest/pkg/sys"
)

func testBuildChart(t *testing.T) (*build, *buildArtifact) {
	t.Helper()
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.chart.source = filepath.Join("..", "..", "charts", "bifroest")
	chart, err := b.chart.create(t.Context(), false)
	require.NoError(t, err)
	require.NotNil(t, chart)
	return b, chart
}

func TestBuildChartIsVersionedReproducibleAndPublishable(t *testing.T) {
	b, chart := testBuildChart(t)
	require.Equal(t, "1.2.3", chart.chartVersion)
	require.Equal(t, "bifroest-1.2.3.tgz", chart.name())
	require.True(t, chart.t.canBePublished())
	require.Equal(t, "application/tar+gzip", chart.mediaType())
	first, err := gos.ReadFile(chart.filepath)
	require.NoError(t, err)
	second, err := b.chart.create(t.Context(), false)
	require.NoError(t, err)
	raw, err := gos.ReadFile(second.filepath)
	require.NoError(t, err)
	require.Equal(t, first, raw)
	updated, err := b.digest.create(t.Context(), buildArtifacts{chart})
	require.NoError(t, err)
	digest, err := gos.ReadFile(updated[1].filepath)
	require.NoError(t, err)
	require.Contains(t, string(digest), chart.name())
}

func TestChartOnlyChangesRunNormalBuildAndTestCI(t *testing.T) {
	raw, err := gos.ReadFile(filepath.Join("..", "..", ".github", "filters.yml"))
	require.NoError(t, err)
	var filters map[string][]any
	require.NoError(t, yaml.Unmarshal(raw, &filters))
	require.Contains(t, filters["go"], "charts/**", "chart-only changes must run existing Go, Helm consumer and build jobs")
}

func TestBuildChartDoesNotRewriteNonSemanticApplicationVersions(t *testing.T) {
	b, bc := testReleaseManifestBuild(t)
	require.NoError(t, bc.version.Set("feature-helm-chart"))
	b.buildContextP.Store(bc)
	chart, err := b.chart.create(t.Context(), false)
	require.NoError(t, err)
	require.Nil(t, chart)
	require.Equal(t, []string{"feature-helm-chart"}, slices.Collect(bc.version.tags("", "latest")))
	b.rawStages = buildStages{buildStageChart}
	_, err = b.chart.create(t.Context(), false)
	require.ErrorContains(t, err, "non-semantic application version")
}

func TestBuildChartStageRunsOnceWithoutPlatformBinaries(t *testing.T) {
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.chart.source = filepath.Join("..", "..", "charts", "bifroest")
	b.rawStages = buildStages{buildStageChart, buildStageDigest}
	artifacts, err := b.buildAll(t.Context(), false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, artifacts.Close()) })
	require.Len(t, slices.Collect(artifacts.onlyOfType(buildArtifactTypeChart)), 1)
	require.Len(t, artifacts, 3, "one chart, one release manifest and one checksum inventory")
}

func TestBuildImageMergeKeepsExistingTagsAndPlatformsWithChart(t *testing.T) {
	b, chart := testBuildChart(t)
	b.versionP.Store(&chart.version)
	b.rawCommit = "revision"
	b.repo.metaP.Store(&github.Repository{HTMLURL: github.String("https://github.com/owner/repository")})
	var artifacts buildArtifacts
	for _, edition := range []sys.Edition{sys.EditionGeneric, sys.EditionExtended} {
		for _, arch := range []sys.Arch{sys.ArchAmd64, sys.ArchArm64} {
			image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: arch.Oci()})
			require.NoError(t, err)
			artifacts = append(artifacts, &buildArtifact{
				Platform:     &bib.Platform{Os: sys.OsLinux, Arch: arch, Edition: edition},
				buildContext: chart.buildContext, t: buildArtifactTypeImage, ociImage: image,
			})
		}
	}
	updated, err := b.image.merge(t.Context(), append(slices.Clone(artifacts), chart))
	require.NoError(t, err)
	for index := range updated.onlyOfType(buildArtifactTypeImagePlatform) {
		manifest, err := index.ociIndex.IndexManifest()
		require.NoError(t, err)
		require.Equal(t, types.OCIImageIndex, manifest.MediaType)
		require.Len(t, manifest.Manifests, 3)
		for _, image := range artifacts {
			if image.Edition != index.Edition {
				continue
			}
			digest, err := image.ociImage.Digest()
			require.NoError(t, err)
			require.True(t, slices.ContainsFunc(manifest.Manifests, func(descriptor v1.Descriptor) bool {
				return descriptor.Digest == digest && descriptor.Platform.OS == "linux" && descriptor.Platform.Architecture == image.Arch.Oci()
			}))
		}
	}
	refs, err := b.image.refs(t.Context(), sys.EditionGeneric)
	require.NoError(t, err)
	require.Len(t, refs, 2)
	require.Equal(t, "ghcr.io/owner/repository:generic-1.2.3", refs[0].Name())
	require.Equal(t, "ghcr.io/owner/repository:1.2.3", refs[1].Name())
}

func TestCombinedChartIsInventoriedWithoutBecomingAPlatform(t *testing.T) {
	b, chart := testBuildChart(t)
	image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	imageIndex := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}})
	combined, err := charts.Combine(imageIndex, chart.ociImage)
	require.NoError(t, err)
	index := &buildArtifact{Platform: &bib.Platform{Edition: sys.EditionGeneric}, buildContext: chart.buildContext, t: buildArtifactTypeImagePlatform, ociIndex: combined}
	artifacts := buildArtifacts{chart, index}
	updated, err := b.releaseManifest.create(t.Context(), artifacts, false)
	require.NoError(t, err)
	raw, err := gos.ReadFile(updated[len(updated)-1].filepath)
	require.NoError(t, err)
	var manifest releaseManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.Empty(t, manifest.Variants)
	require.Len(t, manifest.Assets, 1)
	require.Equal(t, "1.2.3", manifest.Chart.Version)
	require.Equal(t, chart.name(), manifest.Chart.Asset)
	require.Equal(t, "ghcr.io/owner/repository:1.2.3", manifest.Chart.Tag)
	require.Equal(t, string(types.OCIImageIndex), manifest.Chart.IndexMediaType)
	digest, err := combined.Digest()
	require.NoError(t, err)
	require.Equal(t, digest.String(), manifest.Chart.IndexDigest)
	_, err = b.releaseManifest.create(t.Context(), buildArtifacts{chart}, true)
	require.ErrorContains(t, err, "no matching combined generic image index")
	_, err = b.releaseManifest.create(t.Context(), buildArtifacts{index}, false)
	require.ErrorContains(t, err, "unknown chart")
	chart.chartVersion = "1.2.4"
	_, err = b.releaseManifest.create(t.Context(), artifacts, false)
	require.ErrorContains(t, err, "versions do not match")
	chart.chartVersion = "1.2.3"
	require.NoError(t, gos.WriteFile(chart.filepath, []byte("tampered"), 0644))
	_, err = b.releaseManifest.create(t.Context(), artifacts, false)
	require.ErrorContains(t, err, "chart archive digest")
}
