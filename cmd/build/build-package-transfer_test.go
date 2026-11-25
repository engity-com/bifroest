package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	gos "os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/charts"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestPreparedPackagesRoundTripPreservesAllFilesAndOCIBytes(t *testing.T) {
	b, original := testPreparedPackageBuild(t, false)
	require.NoError(t, b.savePreparedPackages(t.Context(), original))
	before, err := packageTransferFiles(b.dest)
	require.NoError(t, err)
	destination := t.TempDir()
	require.NoError(t, gos.CopyFS(destination, gos.DirFS(b.dest)))
	b.dest = destination
	restored, err := b.loadPreparedPackages(t.Context())
	require.NoError(t, err)
	after, err := packageTransferFiles(b.dest)
	require.NoError(t, err)
	require.Equal(t, before, after)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	for _, expected := range original {
		if !expected.t.canBePublished() && expected.t != buildArtifactTypeImagePlatform {
			continue
		}
		index := slices.IndexFunc(restored, func(a *buildArtifact) bool {
			return a.t == expected.t && *a.Platform == *expected.Platform && a.name() == expected.name()
		})
		require.NotEqual(t, -1, index, expected.String())
		actual := restored[index]
		if actual.t != buildArtifactTypeImagePlatform {
			want, err := gos.ReadFile(expected.filepath)
			require.NoError(t, err)
			got, err := gos.ReadFile(actual.filepath)
			require.NoError(t, err)
			require.Equal(t, want, got)
			continue
		}
		want, err := expected.ociIndex.RawManifest()
		require.NoError(t, err)
		got, err := actual.ociIndex.RawManifest()
		require.NoError(t, err)
		require.Equal(t, want, got, "keep exact index bytes, descriptors and chart")
		tag, err := name.NewTag(strings.TrimPrefix(server.URL, "http://") + "/prepared:" + actual.Edition.String())
		require.NoError(t, err)
		require.NoError(t, remote.WriteIndex(tag, actual.ociIndex))
		pushed, err := remote.Index(tag)
		require.NoError(t, err)
		got, err = pushed.RawManifest()
		require.NoError(t, err)
		require.Equal(t, want, got, "publication must push persisted OCI blobs without rebuilding")
	}
	// Without the publish stage this only verifies the transfer; no release exists.
	require.NoError(t, b.publishPreparedPackages(t.Context()))
}

func TestPreparePackagesNeverPublishesEvenWhenPublishStageIsEnabled(t *testing.T) {
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.binaryMode, b.preparePackages = binaryUseExisting, true
	b.rawStages = buildStages{buildStageBinary, buildStageArchive, buildStagePublish}
	b.oses, b.archs, b.editions = sys.Oses{sys.OsLinux}, sys.Archs{sys.ArchAmd64}, sys.Editions{sys.EditionGeneric}
	b.archive.includedResources = nil
	p := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	prefix := p.FilenamePrefix(b.prefix)
	binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, prefix, "existing binary", nil)
	notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, prefix+".third-party-notices.txt", "notice", nil)
	binary.thirdPartyNoticesFilepath, binary.thirdPartyLicenseInventory = notice.filepath, testThirdPartyLicenseInventory()
	testBrowserManifest(t, binary)
	require.NoError(t, b.binary.save(binary, notice))
	t.Chdir(filepath.Join("..", ".."))
	// No GitHub release or registry credentials exist. Accidentally taking the
	// publication branch must fail rather than silently making this test pass.
	artifacts, err := b.buildAll(t.Context(), false)
	require.NoError(t, err)
	require.NoError(t, artifacts.Close())
	_, err = gos.Stat(filepath.Join(b.dest, preparedPackagesFilename))
	require.NoError(t, err)
}

func TestPreparedPackagesRejectEveryMissingOrModifiedFile(t *testing.T) {
	b, artifacts := testPreparedPackageBuild(t, false)
	require.NoError(t, b.savePreparedPackages(t.Context(), artifacts))
	files, err := packageTransferFiles(b.dest)
	require.NoError(t, err)
	for name := range files {
		t.Run(name, func(t *testing.T) {
			filename := filepath.Join(b.dest, filepath.FromSlash(name))
			original, err := gos.ReadFile(filename)
			require.NoError(t, err)
			require.NoError(t, gos.Remove(filename))
			_, err = b.loadPreparedPackages(t.Context())
			require.Error(t, err)
			require.NoError(t, gos.WriteFile(filename, append(slices.Clone(original), '!'), 0644))
			_, err = b.loadPreparedPackages(t.Context())
			require.Error(t, err)
			require.NoError(t, gos.WriteFile(filename, original, 0644))
		})
	}
	_, err = b.loadPreparedPackages(t.Context())
	require.NoError(t, err)
	require.NoError(t, gos.WriteFile(filepath.Join(b.dest, "unexpected"), nil, 0644))
	_, err = b.loadPreparedPackages(t.Context())
	require.Error(t, err)
}

func TestPreparedPackagesRejectChangedContextAndIncompleteArtifactList(t *testing.T) {
	b, artifacts := testPreparedPackageBuild(t, true)
	b.optionsOutputFilename = filepath.Join(t.TempDir(), "github.output")
	require.NoError(t, b.savePreparedPackages(t.Context(), artifacts))
	output, err := gos.ReadFile(b.optionsOutputFilename)
	require.NoError(t, err)
	require.Equal(t, "publish=true\n", string(output))
	filename := filepath.Join(b.dest, preparedPackagesFilename)
	raw, err := gos.ReadFile(filename)
	require.NoError(t, err)
	var original preparedPackages
	require.NoError(t, json.Unmarshal(raw, &original))
	mutations := map[string]func(*preparedPackages){
		"schema":       func(p *preparedPackages) { p.SchemaVersion++ },
		"project":      func(p *preparedPackages) { p.Project = "other/project" },
		"version":      func(p *preparedPackages) { p.Version = "v9.9.9" },
		"revision":     func(p *preparedPackages) { p.Revision = "another-commit" },
		"vendor":       func(p *preparedPackages) { p.Vendor = "other" },
		"time":         func(p *preparedPackages) { p.BuildTime = p.BuildTime.Add(time.Second) },
		"stages":       func(p *preparedPackages) { p.Stages = nil },
		"platforms":    func(p *preparedPackages) { p.Platforms = nil },
		"duplicate":    func(p *preparedPackages) { p.Artifacts = append(p.Artifacts, p.Artifacts[0]) },
		"path":         func(p *preparedPackages) { p.Artifacts[0].Filename = "../outside" },
		"unknown type": func(p *preparedPackages) { p.Artifacts[0].Type = 255 },
		"image digest": func(p *preparedPackages) {
			for i := range p.Artifacts {
				if p.Artifacts[i].Type == buildArtifactTypeImagePlatform {
					p.Artifacts[i].Digest = "sha256:" + strings.Repeat("0", 64)
				}
			}
		},
	}
	for name, mutatePlan := range mutations {
		t.Run(name, func(t *testing.T) {
			var modified preparedPackages
			require.NoError(t, json.Unmarshal(raw, &modified))
			mutatePlan(&modified)
			changed, err := json.Marshal(modified)
			require.NoError(t, err)
			require.NoError(t, gos.WriteFile(filename, changed, 0644))
			_, err = b.loadPreparedPackages(t.Context())
			require.Error(t, err)
		})
	}
	for i, entry := range original.Artifacts {
		t.Run("missing-artifact/"+entry.Filename+entry.Platform.String(), func(t *testing.T) {
			modified := original
			modified.Artifacts = slices.Delete(slices.Clone(original.Artifacts), i, i+1)
			changed, err := json.Marshal(modified)
			require.NoError(t, err)
			require.NoError(t, gos.WriteFile(filename, changed, 0644))
			_, err = b.loadPreparedPackages(t.Context())
			require.Error(t, err, "every prepared archive, SBOM, index, chart, manifest and checksum is mandatory")
		})
	}
	for _, changed := range [][]byte{append(slices.Clone(raw), []byte(" {}")...), bytes.Replace(raw, []byte(`"schemaVersion"`), []byte(`"unknownField"`), 1)} {
		require.NoError(t, gos.WriteFile(filename, changed, 0644))
		_, err = b.loadPreparedPackages(t.Context())
		require.Error(t, err)
	}
	require.NoError(t, gos.WriteFile(filename, raw, 0644))
	_, err = b.loadPreparedPackages(t.Context())
	require.NoError(t, err)
}

func TestPackageTransferRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	directory := t.TempDir()
	require.NoError(t, gos.Symlink(t.TempDir(), filepath.Join(directory, "external")))
	_, err := packageTransferFiles(directory)
	require.ErrorContains(t, err, "non-regular file")
}

func testPreparedPackageBuild(t *testing.T, publish bool) (*build, buildArtifacts) {
	t.Helper()
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.rawStages = allBuildStageVariants.filter(func(stage buildStage) bool { return publish || stage != buildStagePublish })
	b.chart.source = filepath.Join("..", "..", "charts", "bifroest")
	chart, err := b.chart.create(t.Context(), false)
	require.NoError(t, err)
	artifacts := buildArtifacts{chart}
	indexes := make(map[sys.Edition][]mutate.IndexAddendum)
	platformCount := 0
	for p := range b.distributablePlatforms(false) {
		platformCount++
		prefix := p.FilenamePrefix(b.prefix)
		archive := testReleaseManifestFile(t, bc, p, buildArtifactTypeArchive, prefix+bib.ArchiveFormatFor(p.Os).Ext(), "archive:"+p.String(), nil)
		notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, prefix+".third-party-notices.txt", "notice:"+p.String(), nil)
		artifacts = append(artifacts, archive, notice)
		archiveDigest, err := sha256File(archive.filepath)
		require.NoError(t, err)
		subjects := []buildArtifactSbom{{subjectType: buildArtifactTypeArchive, subjectName: archive.name(), subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest}}
		if p.IsImageSupported() {
			platform, err := v1.ParsePlatform(p.Oci())
			require.NoError(t, err)
			var layer bytes.Buffer
			tw := tar.NewWriter(&layer)
			require.NoError(t, tw.WriteHeader(&tar.Header{Name: "bifroest", Mode: 0755, Size: int64(len(prefix))}))
			_, err = io.WriteString(tw, prefix)
			require.NoError(t, err)
			require.NoError(t, tw.Close())
			image, err := mutate.AppendLayers(empty.Image, static.NewLayer(layer.Bytes(), types.OCIUncompressedLayer))
			require.NoError(t, err)
			config, err := image.ConfigFile()
			require.NoError(t, err)
			config.OS, config.Architecture, config.Variant = platform.OS, platform.Architecture, platform.Variant
			image, err = mutate.ConfigFile(image, config)
			require.NoError(t, err)
			descriptor, err := partial.Descriptor(image)
			require.NoError(t, err)
			descriptor.Platform = platform
			indexes[p.Edition] = append(indexes[p.Edition], mutate.IndexAddendum{Add: image, Descriptor: *descriptor})
			subjects = append(subjects, buildArtifactSbom{subjectType: buildArtifactTypeImage, subjectName: prefix + "-image", subjectPlatform: p.Oci(), subjectMediaType: string(descriptor.MediaType), subjectDigest: descriptor.Digest.String()})
		}
		for _, subject := range subjects {
			for _, format := range []struct{ name, suffix string }{{"spdx-2.3", ".spdx.json"}, {"cyclonedx-1.6", ".cdx.json"}} {
				metadata := subject
				metadata.format = format.name
				artifacts = append(artifacts, testReleaseManifestFile(t, bc, p, buildArtifactTypeSbom, subject.subjectName+format.suffix, subject.subjectDigest+format.name, &metadata))
			}
		}
	}
	require.Equal(t, 14, platformCount)
	for edition, adds := range indexes {
		index := mutate.AppendManifests(mutate.IndexMediaType(empty.Index, types.DockerManifestList), adds...)
		index, err = charts.Combine(index, chart.ociImage)
		require.NoError(t, err)
		artifacts = append(artifacts, &buildArtifact{Platform: &bib.Platform{Edition: edition}, buildContext: bc, t: buildArtifactTypeImagePlatform, ociIndex: index})
	}
	artifacts, err = b.releaseManifest.create(t.Context(), artifacts, true)
	require.NoError(t, err)
	artifacts, err = b.digest.create(t.Context(), artifacts)
	require.NoError(t, err)
	return b, artifacts
}
