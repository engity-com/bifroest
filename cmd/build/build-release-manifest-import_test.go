// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	gos "os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestImportPartialReleaseManifestRehydratesDarwinArtifacts(t *testing.T) {
	partialManifest := testPartialDarwinRelease(t, sys.ArchArm64)
	build, buildContext := testReleaseManifestBuild(t)
	local := testArchiveReleaseArtifacts(t, build, buildContext, &bib.Platform{Os: sys.OsWindows, Arch: sys.ArchAmd64, Edition: sys.EditionExtended})

	artifacts, err := build.releaseManifest.importPartial(t.Context(), local, partialManifest)
	require.NoError(t, err)
	require.Len(t, artifacts, 8)
	for index := range local {
		require.Same(t, local[index], artifacts[index])
	}

	byType := make(map[buildArtifactType][]*buildArtifact)
	for _, artifact := range artifacts[len(local):] {
		byType[artifact.t] = append(byType[artifact.t], artifact)
		require.True(t, artifact.t.canBePublished())
		require.Equal(t, sys.OsDarwin, artifact.Os)
		require.Equal(t, sys.ArchArm64, artifact.Arch)
		require.Equal(t, sys.EditionExtended, artifact.Edition)
		require.Equal(t, filepath.Dir(partialManifest), filepath.Dir(artifact.filepath))
	}
	require.Len(t, byType[buildArtifactTypeArchive], 1)
	require.Len(t, byType[buildArtifactTypeNotice], 1)
	require.Len(t, byType[buildArtifactTypeSbom], 2)
	archive := byType[buildArtifactTypeArchive][0]
	archiveDigest, err := sha256File(archive.filepath)
	require.NoError(t, err)
	formats := []string{}
	for _, sbom := range byType[buildArtifactTypeSbom] {
		require.NotNil(t, sbom.sbom)
		require.Equal(t, buildArtifactTypeArchive, sbom.sbom.subjectType)
		require.Equal(t, archive.name(), sbom.sbom.subjectName)
		require.Equal(t, archive.mediaType(), sbom.sbom.subjectMediaType)
		require.Equal(t, archiveDigest, sbom.sbom.subjectDigest)
		formats = append(formats, sbom.sbom.format)
	}
	slices.Sort(formats)
	require.Equal(t, []string{"cyclonedx-1.6", "spdx-2.3"}, formats)
	for _, artifact := range artifacts[len(local):] {
		require.NotEqual(t, buildArtifactTypeManifest, artifact.t)
		require.NotEqual(t, buildArtifactTypeDigest, artifact.t)
	}

	withManifest, err := build.releaseManifest.create(t.Context(), artifacts, true)
	require.NoError(t, err)
	finalArtifacts, err := build.digest.create(t.Context(), withManifest)
	require.NoError(t, err)

	var manifest releaseManifest
	rawManifest, err := gos.ReadFile(buildContext.filepath(releaseManifestFilename))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawManifest, &manifest))
	require.Len(t, manifest.Assets, 8)
	require.Len(t, manifest.Variants, 2)
	require.Equal(t, "darwin", manifest.Variants[0].Os)
	require.Equal(t, "windows", manifest.Variants[1].Os)
	for _, imported := range artifacts[len(local):] {
		require.Contains(t, manifest.Assets, releaseManifestAsset{
			Name:      imported.name(),
			MediaType: imported.mediaType(),
			Digest:    mustSha256File(t, imported.filepath),
		})
	}
	require.Equal(t, buildArtifactTypeDigest, finalArtifacts[len(finalArtifacts)-1].t)
	checksums, err := readReleaseChecksums(buildContext.filepath(releaseChecksumFilename))
	require.NoError(t, err)
	require.Len(t, checksums, 9)
	require.Contains(t, checksums, releaseManifestFilename)
	for _, imported := range artifacts[len(local):] {
		require.Contains(t, checksums, imported.name())
	}
}

func TestImportPartialReleaseManifestsRehydratesBothDarwinArchitectures(t *testing.T) {
	amd64Manifest := testPartialDarwinRelease(t, sys.ArchAmd64)
	arm64Manifest := testPartialDarwinRelease(t, sys.ArchArm64)
	build, buildContext := testReleaseManifestBuild(t)

	artifacts, err := build.releaseManifest.importPartial(t.Context(), nil, amd64Manifest)
	require.NoError(t, err)
	artifacts, err = build.releaseManifest.importPartial(t.Context(), artifacts, arm64Manifest)
	require.NoError(t, err)
	require.Len(t, artifacts, 8)
	require.Equal(t, sys.ArchAmd64, artifacts[0].Arch)
	require.Equal(t, sys.ArchArm64, artifacts[4].Arch)

	withManifest, err := build.releaseManifest.create(t.Context(), artifacts, true)
	require.NoError(t, err)
	_, err = build.digest.create(t.Context(), withManifest)
	require.NoError(t, err)

	var manifest releaseManifest
	rawManifest, err := gos.ReadFile(buildContext.filepath(releaseManifestFilename))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawManifest, &manifest))
	require.Len(t, manifest.Assets, 8)
	require.Len(t, manifest.Variants, 2)
	require.Equal(t, "amd64", manifest.Variants[0].Architecture)
	require.Equal(t, "arm64", manifest.Variants[1].Architecture)
}

func TestImportPartialReleaseManifestRejectsInvalidJSONAndContext(t *testing.T) {
	t.Run("manifest symlink", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		target := manifestFilename + ".real"
		require.NoError(t, gos.Rename(manifestFilename, target))
		require.NoError(t, gos.Symlink(target, manifestFilename))
		testRequireImportError(t, manifestFilename, "not a regular file")
	})

	t.Run("unknown field", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		raw, err := gos.ReadFile(manifestFilename)
		require.NoError(t, err)
		raw = append([]byte(strings.TrimSuffix(string(raw), "}\n")), []byte(",\n  \"unknown\": true\n}\n")...)
		require.NoError(t, gos.WriteFile(manifestFilename, raw, 0644))
		testRequireImportError(t, manifestFilename, "unknown field")
	})

	t.Run("trailing JSON", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		file, err := gos.OpenFile(manifestFilename, gos.O_APPEND|gos.O_WRONLY, 0)
		require.NoError(t, err)
		_, err = file.WriteString("{}\n")
		require.NoError(t, err)
		require.NoError(t, file.Close())
		testRequireImportError(t, manifestFilename, "trailing JSON value")
	})

	tests := map[string]func(*releaseManifest){
		"schema":         func(v *releaseManifest) { v.SchemaVersion++ },
		"project":        func(v *releaseManifest) { v.Project = "other/project" },
		"version":        func(v *releaseManifest) { v.Version = "v9.9.9" },
		"revision":       func(v *releaseManifest) { v.Revision = "other" },
		"created":        func(v *releaseManifest) { v.Created = "2020-01-01T00:00:00Z" },
		"registry":       func(v *releaseManifest) { v.Registry = "registry.invalid/project" },
		"manifest asset": func(v *releaseManifest) { v.ManifestAsset = "other.json" },
		"checksum asset": func(v *releaseManifest) { v.ChecksumAsset = "other.txt" },
	}
	for name, mutate := range tests {
		t.Run(name+" mismatch", func(t *testing.T) {
			manifestFilename := testPartialDarwinRelease(t)
			manifest := testReadReleaseManifest(t, manifestFilename)
			mutate(&manifest)
			testWriteReleaseManifest(t, manifestFilename, manifest)
			testRequireImportError(t, manifestFilename, "mismatch")
		})
	}
}

func TestImportPartialReleaseManifestRejectsInvalidVariantAndAssets(t *testing.T) {
	tests := map[string]struct {
		mutate  func(*releaseManifest)
		message string
	}{
		"extra variant": {
			func(v *releaseManifest) { v.Variants = append(v.Variants, v.Variants[0]) },
			"exactly one variant",
		},
		"wrong platform": {
			func(v *releaseManifest) { v.Variants[0].Architecture = "386" },
			"supported Darwin extended",
		},
		"image": {
			func(v *releaseManifest) { v.Variants[0].Image = &releaseManifestVariantImage{} },
			"must not contain an image",
		},
		"image SBOM": {
			func(v *releaseManifest) {
				v.Variants[0].Sboms.Image = &releaseManifestSbomFiles{Spdx: "image.spdx.json"}
			},
			"must not contain an image",
		},
		"incomplete references": {
			func(v *releaseManifest) { v.Variants[0].Sboms.Archive.CycloneDx = "" },
			"incomplete",
		},
		"traversal": {
			func(v *releaseManifest) { v.Variants[0].Archive = "../archive.tgz" },
			"not a basename",
		},
		"backslash traversal": {
			func(v *releaseManifest) { v.Variants[0].Archive = `..\archive.tgz` },
			"not a basename",
		},
		"duplicate reference": {
			func(v *releaseManifest) { v.Variants[0].Notice = v.Variants[0].Archive },
			"referenced more than once",
		},
		"wrong asset count": {
			func(v *releaseManifest) { v.Assets = v.Assets[:3] },
			"exactly four assets",
		},
		"duplicate asset": {
			func(v *releaseManifest) { v.Assets[1] = v.Assets[0] },
			"duplicate asset name",
		},
		"unreferenced asset": {
			func(v *releaseManifest) { v.Assets[0].Name = "unreferenced.tgz" },
			"not referenced",
		},
		"wrong media type": {
			func(v *releaseManifest) { v.Assets[0].MediaType = "application/octet-stream" },
			"unexpected media type",
		},
		"wrong digest": {
			func(v *releaseManifest) { v.Assets[0].Digest = "sha256:" + strings.Repeat("0", 64) },
			"digest mismatch",
		},
		"noncanonical archive name": {
			func(v *releaseManifest) {
				oldName := v.Variants[0].Archive
				v.Variants[0].Archive = "custom-darwin.tgz"
				for index := range v.Assets {
					if v.Assets[index].Name == oldName {
						v.Assets[index].Name = v.Variants[0].Archive
					}
				}
			},
			"unexpected Darwin release asset",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			manifestFilename := testPartialDarwinRelease(t)
			manifest := testReadReleaseManifest(t, manifestFilename)
			test.mutate(&manifest)
			testWriteReleaseManifest(t, manifestFilename, manifest)
			testRequireImportError(t, manifestFilename, test.message)
		})
	}

	t.Run("archive extension media type", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		manifest := testReadReleaseManifest(t, manifestFilename)
		oldName := manifest.Variants[0].Archive
		newName := strings.TrimSuffix(oldName, ".tgz") + ".zip"
		manifest.Variants[0].Archive = newName
		for index := range manifest.Assets {
			if manifest.Assets[index].Name == oldName {
				manifest.Assets[index].Name = newName
			}
		}
		require.NoError(t, gos.Rename(filepath.Join(filepath.Dir(manifestFilename), oldName), filepath.Join(filepath.Dir(manifestFilename), newName)))
		testWriteReleaseManifest(t, manifestFilename, manifest)
		testRequireImportError(t, manifestFilename, "unexpected Darwin release asset")
	})

	t.Run("corrupt file", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		manifest := testReadReleaseManifest(t, manifestFilename)
		require.NoError(t, gos.WriteFile(filepath.Join(filepath.Dir(manifestFilename), manifest.Variants[0].Archive), []byte("corrupt"), 0644))
		testRequireImportError(t, manifestFilename, "digest mismatch")
	})

	for _, kind := range []string{"symlink", "directory"} {
		t.Run("non-regular "+kind, func(t *testing.T) {
			manifestFilename := testPartialDarwinRelease(t)
			manifest := testReadReleaseManifest(t, manifestFilename)
			assetFilename := filepath.Join(filepath.Dir(manifestFilename), manifest.Variants[0].Notice)
			require.NoError(t, gos.Remove(assetFilename))
			if kind == "symlink" {
				target := filepath.Join(t.TempDir(), "outside")
				require.NoError(t, gos.WriteFile(target, []byte("notice"), 0644))
				require.NoError(t, gos.Symlink(target, assetFilename))
			} else {
				require.NoError(t, gos.Mkdir(assetFilename, 0755))
			}
			testRequireImportError(t, manifestFilename, "not a regular file")
		})
	}

	t.Run("duplicate local artifact", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		manifest := testReadReleaseManifest(t, manifestFilename)
		build, buildContext := testReleaseManifestBuild(t)
		local := testReleaseManifestFile(t, buildContext, &bib.Platform{}, buildArtifactTypeArchive, manifest.Variants[0].Archive, "local", nil)
		_, err := build.releaseManifest.importPartial(t.Context(), buildArtifacts{local}, manifestFilename)
		require.ErrorContains(t, err, "duplicates a local artifact")
	})
}

func TestImportPartialReleaseManifestRejectsInvalidChecksums(t *testing.T) {
	t.Run("non-regular checksum", func(t *testing.T) {
		manifestFilename := testPartialDarwinRelease(t)
		checksumFilename := filepath.Join(filepath.Dir(manifestFilename), releaseChecksumFilename)
		require.NoError(t, gos.Remove(checksumFilename))
		require.NoError(t, gos.Mkdir(checksumFilename, 0755))
		testRequireImportError(t, manifestFilename, "not a regular file")
	})

	tests := map[string]struct {
		mutate  func(string) string
		message string
	}{
		"missing": {
			func(raw string) string { return strings.Join(strings.Split(raw, "\n")[1:], "\n") },
			"cover exactly",
		},
		"extra": {
			func(raw string) string { return raw + strings.Repeat("0", 64) + "  extra\n" },
			"cover exactly",
		},
		"duplicate": {
			func(raw string) string { return raw + strings.Split(raw, "\n")[0] + "\n" },
			"duplicate checksum entry",
		},
		"mismatch": {
			func(raw string) string {
				replacement := "0"
				if raw[0] == '0' {
					replacement = "1"
				}
				return replacement + raw[1:]
			},
			"checksum mismatch",
		},
		"malformed": {
			func(string) string { return "not-a-checksum\n" },
			"malformed checksum line",
		},
		"traversal": {
			func(raw string) string { return raw + strings.Repeat("0", 64) + "  ../extra\n" },
			"not a basename",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			manifestFilename := testPartialDarwinRelease(t)
			checksumFilename := filepath.Join(filepath.Dir(manifestFilename), releaseChecksumFilename)
			raw, err := gos.ReadFile(checksumFilename)
			require.NoError(t, err)
			require.NoError(t, gos.WriteFile(checksumFilename, []byte(test.mutate(string(raw))), 0644))
			testRequireImportError(t, manifestFilename, test.message)
		})
	}
}

func testPartialDarwinRelease(t *testing.T, requested ...sys.Arch) string {
	t.Helper()
	arch := sys.ArchArm64
	if len(requested) > 0 {
		arch = requested[0]
	}
	build, buildContext := testReleaseManifestBuild(t)
	platform := &bib.Platform{Os: sys.OsDarwin, Arch: arch, Edition: sys.EditionExtended}
	archiveName := platform.FilenamePrefix(build.prefix) + ".tgz"
	archive := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeArchive, archiveName, "archive", nil)
	archiveDigest := mustSha256File(t, archive.filepath)
	notice := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeNotice, platform.FilenamePrefix(build.prefix)+".third-party-notices.txt", "notice", nil)
	spdx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".spdx.json", "spdx", &buildArtifactSbom{
		format: "spdx-2.3", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	cycloneDx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".cdx.json", "cyclonedx", &buildArtifactSbom{
		format: "cyclonedx-1.6", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	withManifest, err := build.releaseManifest.create(t.Context(), buildArtifacts{archive, notice, spdx, cycloneDx}, false)
	require.NoError(t, err)
	_, err = build.digest.create(t.Context(), withManifest)
	require.NoError(t, err)
	return buildContext.filepath(releaseManifestFilename)
}

func testArchiveReleaseArtifacts(t *testing.T, build *build, buildContext *buildContext, platform *bib.Platform) buildArtifacts {
	t.Helper()
	archiveName := platform.FilenamePrefix(build.prefix) + bib.ArchiveFormatFor(platform.Os).Ext()
	archive := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeArchive, archiveName, "archive", nil)
	archiveDigest := mustSha256File(t, archive.filepath)
	notice := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeNotice, platform.FilenamePrefix(build.prefix)+".third-party-notices.txt", "notice", nil)
	spdx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".spdx.json", "spdx", &buildArtifactSbom{
		format: "spdx-2.3", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	cycloneDx := testReleaseManifestFile(t, buildContext, platform, buildArtifactTypeSbom, archiveName+".cdx.json", "cyclonedx", &buildArtifactSbom{
		format: "cyclonedx-1.6", subjectType: buildArtifactTypeArchive, subjectName: archiveName, subjectMediaType: archive.mediaType(), subjectDigest: archiveDigest,
	})
	return buildArtifacts{archive, notice, spdx, cycloneDx}
}

func testReadReleaseManifest(t *testing.T, filename string) releaseManifest {
	t.Helper()
	var result releaseManifest
	raw, err := gos.ReadFile(filename)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &result))
	return result
}

func testWriteReleaseManifest(t *testing.T, filename string, manifest releaseManifest) {
	t.Helper()
	raw, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, gos.WriteFile(filename, append(raw, '\n'), 0644))
}

func testRequireImportError(t *testing.T, manifestFilename, message string) {
	t.Helper()
	build, _ := testReleaseManifestBuild(t)
	_, err := build.releaseManifest.importPartial(t.Context(), nil, manifestFilename)
	require.ErrorContains(t, err, message)
}

func mustSha256File(t *testing.T, filename string) string {
	t.Helper()
	digest, err := sha256File(filename)
	require.NoError(t, err)
	return digest
}
