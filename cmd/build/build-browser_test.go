package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	gos "os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/engity-com/bifroest/internal/build/browser"
	"github.com/stretchr/testify/require"
)

func testBrowserManifest(t *testing.T, binary *buildArtifact) {
	t.Helper()
	raw, err := gos.ReadFile("../../internal/build/browser/testdata/minimal.json")
	require.NoError(t, err)
	m, err := browser.Decode(raw)
	require.NoError(t, err)
	binary.buildContext.revision = m.Revision
	require.NoError(t, stageBrowserBuild(binary, m, raw))
	if binary.thirdPartyLicenseInventory != nil {
		binary.thirdPartyLicenseInventory.browser, binary.thirdPartyLicenseInventory.browserDigest = m, browserManifestDigest(raw)
	}
}

func TestBrowserBuildRequiresExactOutputsInputsAndRevision(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	raw, err := gos.ReadFile("../../internal/build/browser/testdata/minimal.json")
	require.NoError(t, err)
	m, err := browser.Decode(raw)
	require.NoError(t, err)
	root := fstest.MapFS{browserAssetDirectory + "/" + browser.Filename: &fstest.MapFile{Data: raw}}
	for _, file := range m.Assets {
		root[browserAssetDirectory+"/"+file.Name] = &fstest.MapFile{}
	}
	for _, file := range m.Inputs {
		root[file.Name] = &fstest.MapFile{}
	}
	_, _, err = readBrowserBuild(root, m.Revision)
	require.NoError(t, err)
	_, _, err = readBrowserBuild(root, strings.Repeat("b", 40))
	require.ErrorContains(t, err, "revision")
	root["go.mod"].Data = []byte("changed input")
	_, _, err = readBrowserBuild(root, m.Revision)
	require.Error(t, err)
	root["go.mod"].Data = nil
	m.Dirty = true
	raw, err = json.Marshal(m)
	require.NoError(t, err)
	root[browserAssetDirectory+"/"+browser.Filename].Data = raw
	t.Setenv("GITHUB_ACTIONS", "true")
	_, _, err = readBrowserBuild(root, m.Revision)
	require.ErrorContains(t, err, "clean")
}

func TestBrowserManifestIsIncludedInArchivesAndPackagingRejectsTampering(t *testing.T) {
	build, bc := testReleaseManifestBuild(t)
	build.buildContextP.Store(bc)
	binary := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeBinary, "bifroest-linux-amd64-generic", "binary", nil)
	notice := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeNotice, "bifroest-linux-amd64-generic.third-party-notices.txt", "notice", nil)
	binary.thirdPartyNoticesFilepath = notice.filepath
	binary.thirdPartyLicenseInventory = testThirdPartyLicenseInventory()
	testBrowserManifest(t, binary)
	require.NoError(t, build.binary.save(binary, notice))
	loaded, _, err := build.binary.load(t.Context(), binary.Platform)
	require.NoError(t, err)
	var output bytes.Buffer
	writer, err := build.archive.newTgzWriter(bc.time, &output)
	require.NoError(t, err)
	require.NoError(t, writer.addFile(browser.ArchiveFilename, browserBuildPath(loaded), 0644))
	require.NoError(t, writer.Close())
	gz, err := gzip.NewReader(bytes.NewReader(output.Bytes()))
	require.NoError(t, err)
	defer gz.Close()
	reader := tar.NewReader(gz)
	header, err := reader.Next()
	require.NoError(t, err)
	require.Equal(t, browser.ArchiveFilename, header.Name)
	actual, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, binary.browserManifestRaw, actual)
	require.NoError(t, gos.WriteFile(browserBuildPath(binary), []byte("tampered manifest"), 0644))
	_, _, err = build.binary.load(t.Context(), binary.Platform)
	require.ErrorContains(t, err, "has digest")
}

func TestBrowserSbomEnrichmentHasExactAssetHashesAndSeparateSourceClaims(t *testing.T) {
	_, bc := testReleaseManifestBuild(t)
	binary := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeBinary, "binary", "binary", nil)
	binary.thirdPartyLicenseInventory = testThirdPartyLicenseInventory()
	testBrowserManifest(t, binary)
	for _, format := range []string{"spdx-json@2.3", "cyclonedx-json@1.6"} {
		document := map[string]any{"packages": []any{map[string]any{"name": "artifact", "SPDXID": "SPDXRef-Root"}}, "components": []any{}, "metadata": map[string]any{"component": map[string]any{"name": "artifact", "bom-ref": "root"}}}
		require.NoError(t, enrichBrowserSbom(document, format, "artifact", binary.thirdPartyLicenseInventory))
		first, err := json.Marshal(document)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(first, &document))
		require.NoError(t, enrichBrowserSbom(document, format, "artifact", binary.thirdPartyLicenseInventory))
		second, err := json.Marshal(document)
		require.NoError(t, err)
		require.Equal(t, first, second)
		require.Contains(t, string(second), "not exact tree-shaken usage")
		require.Contains(t, string(second), "pkg:npm/%40fixture/library@1.2.3")
		require.Contains(t, string(second), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		require.Contains(t, string(second), browserManifestDigest(binary.browserManifestRaw))
	}
}

func TestBinaryPackagingRejectsMissingOldAndWrongRevisionBrowserInventory(t *testing.T) {
	for _, mode := range []string{"missing", "old metadata", "wrong revision", "null clean state"} {
		t.Run(mode, func(t *testing.T) {
			build, bc := testReleaseManifestBuild(t)
			build.buildContextP.Store(bc)
			binary := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeBinary, "bifroest-linux-amd64-generic", "binary", nil)
			notice := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeNotice, "bifroest-linux-amd64-generic.third-party-notices.txt", "notice", nil)
			binary.thirdPartyNoticesFilepath, binary.thirdPartyLicenseInventory = notice.filepath, testThirdPartyLicenseInventory()
			testBrowserManifest(t, binary)
			require.NoError(t, build.binary.save(binary, notice))
			metadataFile := build.binary.metadataFilepath(binary)
			raw, err := gos.ReadFile(metadataFile)
			require.NoError(t, err)
			var metadata binaryBuildMetadata
			require.NoError(t, json.Unmarshal(raw, &metadata))
			switch mode {
			case "missing":
				require.NoError(t, gos.Remove(browserBuildPath(binary)))
			case "old metadata":
				metadata.SchemaVersion = 1
			case "wrong revision":
				manifest := *binary.browserManifest
				manifest.Revision = strings.Repeat("b", 40)
				image, err := json.Marshal(manifest)
				require.NoError(t, err)
				require.NoError(t, gos.WriteFile(browserBuildPath(binary), image, 0644))
				metadata.BrowserDigest = browserManifestDigest(image)
			case "null clean state":
				image := bytes.Replace(binary.browserManifestRaw, []byte(`"dirty": false`), []byte(`"dirty": null`), 1)
				require.NoError(t, gos.WriteFile(browserBuildPath(binary), image, 0644))
				metadata.BrowserDigest = browserManifestDigest(image)
			}
			raw, err = json.Marshal(metadata)
			require.NoError(t, err)
			require.NoError(t, gos.WriteFile(metadataFile, raw, 0644))
			_, _, err = build.binary.load(t.Context(), binary.Platform)
			require.Error(t, err)
		})
	}
}

func TestReleaseManifestRecordsBrowserBuildDigest(t *testing.T) {
	build, bc := testReleaseManifestBuild(t)
	archive := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeArchive, "bifroest-linux-amd64-generic.tgz", "archive", nil)
	archive.thirdPartyLicenseInventory = testThirdPartyLicenseInventory()
	testBrowserManifest(t, archive)
	notice := testReleaseManifestFile(t, bc, &testSbomPlatform, buildArtifactTypeNotice, "bifroest-linux-amd64-generic.third-party-notices.txt", "notice", nil)
	result, err := build.releaseManifest.create(t.Context(), buildArtifacts{archive, notice}, false)
	require.NoError(t, err)
	raw, err := gos.ReadFile(result[len(result)-1].filepath)
	require.NoError(t, err)
	var manifest releaseManifest
	require.NoError(t, json.Unmarshal(raw, &manifest))
	require.Equal(t, archive.thirdPartyLicenseInventory.browserDigest, manifest.Variants[0].BrowserBuildDigest)
}

func TestBuiltBrowserReleaseInventoryMatchesActualSources(t *testing.T) {
	if gos.Getenv("BIFROEST_TEST_BROWSER_CLIENT") != "1" {
		t.Skip("enable the existing built-browser test opt-in")
	}
	root := gos.DirFS("../..")
	m, raw, err := browser.Read(root, browserAssetDirectory+"/"+browser.Filename)
	require.NoError(t, err)
	verified, image, err := readBrowserBuild(root, m.Revision)
	require.NoError(t, err)
	require.Equal(t, raw, image)
	require.Equal(t, m, verified)
	for _, name := range []string{"web/bun.lock", "web/.tool-versions", "pkg/recording/cast/verifier.go", "cmd/browser-evidence/main_js.go"} {
		found := false
		for _, input := range m.Inputs {
			if input.Name == name {
				found = true
			}
		}
		require.True(t, found, name)
	}
	for _, ecosystem := range []string{"npm", "golang", "go-runtime"} {
		found := false
		for _, component := range m.Components {
			if component.Ecosystem == ecosystem {
				found = true
			}
		}
		require.True(t, found, ecosystem)
	}
}
