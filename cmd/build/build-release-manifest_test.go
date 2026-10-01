// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	gos "os"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestReleaseManifestIsDeterministicAndRelatesComplianceArtifacts(t *testing.T) {
	build, buildContext := testReleaseManifestBuild(t)
	platform := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	archiveName := "bifroest-linux-amd64-generic.tgz"
	archive := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeArchive, archiveName, "archive", nil)
	archiveDigest, err := sha256File(archive.filepath)
	require.NoError(t, err)
	notice := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeNotice, "bifroest-linux-amd64-generic.third-party-notices.txt", "notice", nil)
	imageDigest, err := empty.Image.Digest()
	require.NoError(t, err)
	imageMediaType, err := empty.Image.MediaType()
	require.NoError(t, err)
	indexMediaType, err := empty.Index.MediaType()
	require.NoError(t, err)
	archiveSpdx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".spdx.json", "archive spdx", &buildArtifactSbom{
		format: "spdx-2.3", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	archiveCycloneDx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".cdx.json", "archive cyclonedx", &buildArtifactSbom{
		format: "cyclonedx-1.6", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	imageName := "bifroest-image-linux-amd64-generic"
	imageSpdx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, imageName+".spdx.json", "image spdx", &buildArtifactSbom{
		format: "spdx-2.3", subjectType: buildArtifactTypeImage, subjectName: imageName, subjectMediaType: string(imageMediaType), subjectPlatform: "linux/amd64", subjectDigest: imageDigest.String(),
	})
	imageCycloneDx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, imageName+".cdx.json", "image cyclonedx", &buildArtifactSbom{
		format: "cyclonedx-1.6", subjectType: buildArtifactTypeImage, subjectName: imageName, subjectMediaType: string(imageMediaType), subjectPlatform: "linux/amd64", subjectDigest: imageDigest.String(),
	})
	imageDescriptor, err := partial.Descriptor(empty.Image)
	require.NoError(t, err)
	imageDescriptor.Platform = &v1.Platform{OS: "linux", Architecture: "amd64"}
	imageIndex := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: empty.Image, Descriptor: *imageDescriptor})
	index := &buildArtifact{
		Platform:     &bib.Platform{Edition: sys.EditionGeneric},
		buildContext: buildContext,
		t:            buildArtifactTypeImagePlatform,
		ociIndex:     imageIndex,
	}
	artifacts := buildArtifacts{imageCycloneDx, archive, index, notice, archiveSpdx, imageSpdx, archiveCycloneDx}

	created, err := build.releaseManifest.create(t.Context(), artifacts, true)
	require.NoError(t, err)
	first, err := gos.ReadFile(created[len(created)-1].filepath)
	require.NoError(t, err)

	permuted := slices.Clone(artifacts)
	slices.Reverse(permuted)
	_, err = build.releaseManifest.create(t.Context(), permuted, true)
	require.NoError(t, err)
	second, err := gos.ReadFile(buildContext.filepath(releaseManifestFilename))
	require.NoError(t, err)
	require.Equal(t, first, second)

	var manifest releaseManifest
	require.NoError(t, json.Unmarshal(first, &manifest))
	require.Equal(t, 1, manifest.SchemaVersion)
	require.Equal(t, "owner/repository", manifest.Project)
	require.Equal(t, "v1.2.3", manifest.Version)
	require.Equal(t, "revision", manifest.Revision)
	require.Len(t, manifest.Assets, 6)
	require.True(t, slices.IsSortedFunc(manifest.Assets, func(a, b releaseManifestAsset) int { return strings.Compare(a.Name, b.Name) }))
	require.Len(t, manifest.Variants, 1)
	variant := manifest.Variants[0]
	require.Equal(t, archive.name(), variant.Archive)
	require.Equal(t, notice.name(), variant.Notice)
	require.Equal(t, archiveSpdx.name(), variant.Sboms.Archive.Spdx)
	require.Equal(t, archiveCycloneDx.name(), variant.Sboms.Archive.CycloneDx)
	require.Equal(t, imageSpdx.name(), variant.Sboms.Image.Spdx)
	require.Equal(t, imageCycloneDx.name(), variant.Sboms.Image.CycloneDx)
	require.Equal(t, "ghcr.io/owner/repository:generic-1.2.3", variant.Image.Tag)
	require.Equal(t, string(indexMediaType), variant.Image.IndexMediaType)
	require.Equal(t, "linux/amd64", variant.Image.Platform)
	require.Equal(t, imageDigest.String(), variant.Image.PlatformDigest)
	require.Equal(t, string(imageMediaType), variant.Image.PlatformMediaType)
	require.Contains(t, variant.Image.IndexReference, "ghcr.io/owner/repository@sha256:")

	unknownDigest := "sha256:" + strings.Repeat("0", 64)
	imageSpdx.sbom.subjectDigest = unknownDigest
	imageCycloneDx.sbom.subjectDigest = unknownDigest
	_, err = build.releaseManifest.create(t.Context(), artifacts, true)
	require.ErrorContains(t, err, "does not contain image digest")
}

func TestReleaseManifestRejectsDuplicateAndIncompleteVariantArtifacts(t *testing.T) {
	build, buildContext := testReleaseManifestBuild(t)
	platform := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	archive := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeArchive, "bifroest-linux-amd64-generic.tgz", "archive", nil)
	notice := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeNotice, "bifroest-linux-amd64-generic.third-party-notices.txt", "notice", nil)

	_, err := build.releaseManifest.create(t.Context(), buildArtifacts{archive, notice}, true)
	require.ErrorContains(t, err, "incomplete SBOM formats")
	created, err := build.releaseManifest.create(t.Context(), buildArtifacts{archive, notice}, false)
	require.NoError(t, err)
	require.Len(t, created, 3)

	duplicateArchive := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeArchive, "bifroest-linux-amd64-generic.zip", "duplicate", nil)
	_, err = build.releaseManifest.create(t.Context(), buildArtifacts{archive, duplicateArchive}, true)
	require.ErrorContains(t, err, "duplicate archive")
}

func TestComplianceArtifactsArePublishable(t *testing.T) {
	for _, artifactType := range []buildArtifactType{buildArtifactTypeNotice, buildArtifactTypeManifest} {
		require.True(t, artifactType.canBePublished())
	}
	require.Equal(t, "text/plain; charset=utf-8", (&buildArtifact{t: buildArtifactTypeNotice, filepath: "notice.txt"}).mediaType())
	require.Equal(t, "application/json", (&buildArtifact{t: buildArtifactTypeManifest, filepath: "manifest.json"}).mediaType())
}

func TestBuildPlatformsAreSorted(t *testing.T) {
	base := &base{}
	build := newBuild(base)
	var names []string
	for platform := range build.allPlatforms(false) {
		names = append(names, platform.FilenamePrefix(build.prefix))
	}
	require.True(t, slices.IsSorted(names))
}

func testReleaseManifestBuild(t *testing.T) (*build, *buildContext) {
	t.Helper()
	base := &base{}
	repository := newRepo(base)
	repository.owner = owner("owner")
	repository.name = repoName("repository")
	base.repo = repository
	build := newBuild(base)
	build.dest = t.TempDir()
	var version version
	require.NoError(t, version.Set("v1.2.3"))
	buildContext := &buildContext{
		build:    build,
		version:  version,
		time:     time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC),
		vendor:   "Engity GmbH",
		revision: "revision",
	}
	return build, buildContext
}

func testReleaseManifestFile(t *testing.T, buildContext *buildContext, platform *bib.Platform, artifactType buildArtifactType, name, content string, sbom *buildArtifactSbom) *buildArtifact {
	t.Helper()
	filename := buildContext.filepath(name)
	require.NoError(t, gos.WriteFile(filename, []byte(content), 0644))
	return &buildArtifact{Platform: platform, buildContext: buildContext, t: artifactType, filepath: filename, sbom: sbom}
}
