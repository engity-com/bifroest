package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

func testReleaseDescriptionSource() releaseDescriptionSource {
	manifest := releaseManifest{
		SchemaVersion: 2, Project: "owner/repository", Version: "v1.2.3-beta1", Registry: "ghcr.io/owner/repository",
		ManifestAsset: releaseManifestFilename, ChecksumAsset: "bifroest-checksums.txt",
	}
	for _, platform := range []string{"linux/amd64/generic", "linux/amd64/extended", "linux/arm64/generic", "darwin/arm64/generic", "windows/amd64/generic"} {
		parts := strings.Split(platform, "/")
		name := "bifroest-" + strings.ReplaceAll(platform, "/", "-")
		archive := name + ".tgz"
		if parts[0] == "windows" {
			archive = name + ".zip"
		}
		variant := releaseManifestVariant{Os: parts[0], Architecture: parts[1], Edition: parts[2], Archive: archive,
			Sboms: releaseManifestVariantSboms{Archive: &releaseManifestSbomFiles{Spdx: archive + ".spdx.json", CycloneDx: archive + ".cdx.json"}},
		}
		names := []string{archive, variant.Sboms.Archive.Spdx, variant.Sboms.Archive.CycloneDx}
		if parts[0] != "darwin" {
			variant.Image = &releaseManifestVariantImage{Tag: manifest.Registry + ":" + parts[2] + "-1.2.3-beta1"}
			variant.Sboms.Image = &releaseManifestSbomFiles{Spdx: name + "-image.spdx.json", CycloneDx: name + "-image.cdx.json"}
			names = append(names, variant.Sboms.Image.Spdx, variant.Sboms.Image.CycloneDx)
		}
		for _, name := range names {
			manifest.Assets = append(manifest.Assets, releaseManifestAsset{Name: name, Digest: "sha256:" + strings.Repeat("a", 64)})
		}
		manifest.Variants = append(manifest.Variants, variant)
	}
	source := releaseDescriptionSource{Manifest: manifest, Release: &github.RepositoryRelease{
		ID: github.Int64(100), TagName: github.String(manifest.Version), Prerelease: github.Bool(true),
		Body: github.String("Manual notes\n\n" + releaseArtifactsPlaceholder + "\n\nMore notes"),
	}}
	source.Release.Assets = append(source.Release.Assets,
		&github.ReleaseAsset{ID: github.Int64(1), Name: github.String(manifest.ManifestAsset)},
		&github.ReleaseAsset{ID: github.Int64(2), Name: github.String(manifest.ChecksumAsset)})
	for index, asset := range manifest.Assets {
		source.Release.Assets = append(source.Release.Assets, &github.ReleaseAsset{ID: github.Int64(int64(index + 3)), Name: github.String(asset.Name)})
	}
	return source
}

func TestReleaseDescriptionRendersEveryAssetAndOnlyRequestedImageColumns(t *testing.T) {
	source := testReleaseDescriptionSource()
	require.NoError(t, validateReleaseDescriptionSource(source, "owner/repository", "v1.2.3-beta1"))
	view, err := newReleaseDescriptionView(source)
	require.NoError(t, err)
	fragment := renderReleaseDescription(view)
	require.Contains(t, fragment, "## Downloads")
	require.Contains(t, fragment, "## Docker/OCI images")
	require.NotContains(t, fragment, "## Helm chart")
	require.NotContains(t, fragment, "Reference</th>")
	require.NotContains(t, fragment, "onclick")
	require.NotContains(t, fragment, "<svg")
	require.NotContains(t, fragment, "style=")
	require.Contains(t, fragment, "<th colspan=\"3\" align=\"center\">macOS</th>")
	require.Contains(t, fragment, "<th colspan=\"2\" align=\"center\">macOS</th>")
	require.Contains(t, fragment, "Generic / Extended")
	require.NotContains(t, fragment, "Unversioned tags")
	require.NotContains(t, fragment, "current stable release")
	require.Equal(t, []string{"docker pull ghcr.io/owner/repository:generic-1.2.3-beta1", "docker pull ghcr.io/owner/repository:extended-1.2.3-beta1"}, view.PullCommands)
	require.Equal(t, 2, strings.Count(fragment, "docker pull "))
	for _, asset := range source.Manifest.Assets {
		require.Contains(t, fragment, "/releases/download/v1.2.3-beta1/"+asset.Name)
	}
	require.Contains(t, fragment, "https://bifroest.engity.org/v1.2.3-beta1/setup/in-docker/")
	var preview bytes.Buffer
	require.NoError(t, renderReleaseDescriptionPreview(&preview, view))
	require.Contains(t, preview.String(), "No GitHub release was changed")
	icons := strings.NewReplacer(
		releaseDescriptionDownloadIconURL, releaseDescriptionDownloadIconFilename,
		releaseDescriptionUnavailableIconURL, releaseDescriptionUnavailableIconFilename,
		releaseDescriptionSeparatorIconURL, releaseDescriptionSeparatorIconFilename,
	)
	require.Contains(t, preview.String(), icons.Replace(string(view.ArchiveTable)))
	require.Contains(t, preview.String(), icons.Replace(string(view.ImageTable)))
	require.Contains(t, preview.String(), "img-src 'self'")
	require.NotContains(t, preview.String(), releaseDescriptionDownloadIconURL)
	require.NotContains(t, preview.String(), releaseDescriptionUnavailableIconURL)
	require.NotContains(t, preview.String(), releaseDescriptionSeparatorIconURL)
	require.NotContains(t, preview.String(), "data:")
	require.NotContains(t, preview.String(), "Unversioned tags")
	require.Equal(t, 2, strings.Count(preview.String(), "docker pull "))
	require.NotContains(t, fragment, "data:")
	_, err = html.Parse(strings.NewReader(preview.String()))
	require.NoError(t, err)
}

func TestReleaseDescriptionTablesUseGitHubCompatibleIconsAndAlignment(t *testing.T) {
	view, err := newReleaseDescriptionView(testReleaseDescriptionSource())
	require.NoError(t, err)
	for _, table := range []string{string(view.ArchiveTable), string(view.ImageTable)} {
		document, err := html.Parse(strings.NewReader(table))
		require.NoError(t, err)
		images := 0
		downloads := 0
		unavailable := 0
		separators := 0
		artifactCells := 0
		cells := 0
		for node := range document.Descendants() {
			if node.Type != html.ElementNode {
				continue
			}
			attributes := make(map[string]string)
			for _, attribute := range node.Attr {
				attributes[attribute.Key] = attribute.Val
			}
			switch node.Data {
			case "td", "th":
				cells++
				if node.Parent.FirstChild == node {
					// The first header of the second row is a data column, not Architecture.
					if node.Data == "td" || attributes["rowspan"] == "2" {
						require.Equal(t, "left", attributes["align"])
						continue
					}
				}
				require.Equal(t, "center", attributes["align"])
				if node.Data == "td" {
					artifactCells++
					for child := range node.ChildNodes() {
						if child.Type == html.TextNode {
							require.Empty(t, strings.TrimSpace(child.Data), "icons and separator must not mix SVGs with text glyphs")
						}
					}
				}
			case "img":
				images++
				width := "16"
				switch attributes["src"] {
				case releaseDescriptionDownloadIconURL:
					downloads++
					require.Equal(t, "a", node.Parent.Data)
				case releaseDescriptionUnavailableIconURL:
					unavailable++
					require.Equal(t, "td", node.Parent.Data)
					require.Contains(t, attributes["title"], "is not available")
					require.Equal(t, attributes["title"], attributes["aria-label"])
				case releaseDescriptionSeparatorIconURL:
					separators++
					width = "8"
					require.Equal(t, "td", node.Parent.Data)
					require.Equal(t, "true", attributes["aria-hidden"])
				default:
					t.Fatalf("unexpected release icon URL %q", attributes["src"])
				}
				require.Equal(t, width, attributes["width"])
				require.Equal(t, "16", attributes["height"])
				require.Equal(t, "middle", attributes["align"])
				require.NotEmpty(t, attributes["alt"])
			}
		}
		require.Positive(t, cells)
		require.Positive(t, images)
		require.Positive(t, downloads)
		require.Positive(t, unavailable)
		require.Equal(t, artifactCells, separators)
		require.Equal(t, 3*artifactCells, images, "each cell must contain two icons and one SVG separator")
	}
}

func TestReleaseDescriptionIncludesHelmOnlyForPublishedMatchingChart(t *testing.T) {
	source := testReleaseDescriptionSource()
	source.Manifest.Chart = &releaseManifestChart{Version: "1.2.3-beta1", Asset: "bifroest-1.2.3-beta1.tgz"}
	source.Manifest.Assets = append(source.Manifest.Assets, releaseManifestAsset{Name: source.Manifest.Chart.Asset, Digest: "sha256:" + strings.Repeat("a", 64)})
	source.Release.Assets = append(source.Release.Assets, &github.ReleaseAsset{Name: github.String(source.Manifest.Chart.Asset)})
	require.NoError(t, validateReleaseDescriptionSource(source, "owner/repository", source.Manifest.Version))
	view, err := newReleaseDescriptionView(source)
	require.NoError(t, err)
	fragment := renderReleaseDescription(view)
	require.Contains(t, fragment, "## Helm chart")
	require.Contains(t, fragment, "helm pull oci://ghcr.io/owner/repository --version 1.2.3-beta1")
	require.NotContains(t, fragment, "--version latest")
	source.Manifest.Chart.Version = "1.2.4"
	require.ErrorContains(t, validateReleaseDescriptionSource(source, "owner/repository", source.Manifest.Version), "chart version")
}

func TestReleaseDescriptionManifestValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		modify func(*releaseDescriptionSource)
	}{
		{"schema", func(s *releaseDescriptionSource) { s.Manifest.SchemaVersion = 99 }},
		{"project", func(s *releaseDescriptionSource) { s.Manifest.Project = "another/project" }},
		{"version", func(s *releaseDescriptionSource) { s.Manifest.Version = "v1.2.4" }},
		{"draft", func(s *releaseDescriptionSource) { s.Release.Draft = github.Bool(true) }},
		{"prerelease", func(s *releaseDescriptionSource) { s.Release.Prerelease = github.Bool(false) }},
		{"registry", func(s *releaseDescriptionSource) { s.Manifest.Registry = "evil.example/image" }},
		{"missing asset", func(s *releaseDescriptionSource) { s.Release.Assets = s.Release.Assets[1:] }},
		{"duplicate asset", func(s *releaseDescriptionSource) { s.Release.Assets = append(s.Release.Assets, s.Release.Assets[0]) }},
		{"unexpected asset", func(s *releaseDescriptionSource) {
			s.Release.Assets = append(s.Release.Assets, &github.ReleaseAsset{Name: github.String("unexpected.txt")})
		}},
		{"unknown archive", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Archive = "missing.tgz" }},
		{"unknown SBOM", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Sboms.Archive.Spdx = "missing.json" }},
		{"missing SBOM", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Sboms.Archive = nil }},
		{"image without SBOM", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Sboms.Image = nil }},
		{"SBOM without image", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Image = nil }},
		{"duplicate variant", func(s *releaseDescriptionSource) {
			s.Manifest.Variants = append(s.Manifest.Variants, s.Manifest.Variants[0])
		}},
		{"no variants", func(s *releaseDescriptionSource) { s.Manifest.Variants = nil }},
		{"platform", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Os = "<script>" }},
		{"architecture", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Architecture = "unknown" }},
		{"edition", func(s *releaseDescriptionSource) { s.Manifest.Variants[0].Edition = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := testReleaseDescriptionSource()
			test.modify(&source)
			require.Error(t, validateReleaseDescriptionSource(source, "owner/repository", "v1.2.3-beta1"))
		})
	}
	source := testReleaseDescriptionSource()
	source.Manifest.SchemaVersion = 1
	require.NoError(t, validateReleaseDescriptionSource(source, "owner/repository", source.Manifest.Version))
}

type releaseDescriptionTestAPI struct {
	sync.Mutex
	source        releaseDescriptionSource
	requests      []string
	patches       []map[string]json.RawMessage
	getCount      int
	currentBody   string
	currentBroken bool
}

func (api *releaseDescriptionTestAPI) serve(response http.ResponseWriter, request *http.Request) {
	api.Lock()
	defer api.Unlock()
	api.requests = append(api.requests, request.Method+" "+request.URL.RequestURI())
	response.Header().Set("Content-Type", "application/json")
	switch request.Method + " " + request.URL.Path {
	case "GET /repos/owner/repository/releases/tags/v1.2.3-beta1":
		release := *api.source.Release
		api.getCount++
		if api.getCount > 1 && api.currentBody != "" {
			release.Body = github.String(api.currentBody)
		}
		if api.currentBroken && api.getCount > 1 {
			release.Draft = github.Bool(true)
		}
		release.Assets = nil // Require the caller to use the paginated inventory.
		_ = json.NewEncoder(response).Encode(&release)
	case "GET /repos/owner/repository/releases/100/assets":
		page, _ := strconv.Atoi(request.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		start := (page - 1) * 100
		end := min(start+100, len(api.source.Release.Assets))
		if end < len(api.source.Release.Assets) {
			response.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=%d&per_page=100>; rel="next"`, request.Host, request.URL.Path, page+1))
		}
		_ = json.NewEncoder(response).Encode(api.source.Release.Assets[start:end])
	case "GET /repos/owner/repository/releases/assets/1":
		_ = json.NewEncoder(response).Encode(api.source.Manifest)
	case "PATCH /repos/owner/repository/releases/100":
		var body map[string]json.RawMessage
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		api.patches = append(api.patches, body)
		var description string
		_ = json.Unmarshal(body["body"], &description)
		api.source.Release.Body = github.String(description)
		api.currentBody = description
		_ = json.NewEncoder(response).Encode(api.source.Release)
	default:
		http.Error(response, "unexpected API request", http.StatusNotFound)
	}
}

func TestReleaseDescriptionPreviewIsReadOnlyAndPaginatesAssets(t *testing.T) {
	source := testReleaseDescriptionSource()
	for index := 0; index < 105; index++ {
		name := fmt.Sprintf("extra-notice-%03d.txt", index)
		source.Manifest.Assets = append(source.Manifest.Assets, releaseManifestAsset{Name: name, Digest: "sha256:" + strings.Repeat("a", 64)})
		source.Release.Assets = append(source.Release.Assets, &github.ReleaseAsset{Name: github.String(name)})
	}
	api := &releaseDescriptionTestAPI{source: source}
	client := newDependencyTestGitHubClient(t, api.serve)
	repository := newDependencyTestRepo(client)
	options := &releaseDescriptionOptions{repository: repository, tag: "1.2.3-beta1", output: t.TempDir()}
	require.NoError(t, options.run(t.Context(), false))
	api.Lock()
	defer api.Unlock()
	require.Empty(t, api.patches)
	require.Contains(t, strings.Join(api.requests, "\n"), "page=2")
	for _, request := range api.requests {
		require.True(t, strings.HasPrefix(request, "GET "), request)
	}
	for _, name := range []string{"preview.html", releaseDescriptionDownloadIconFilename, releaseDescriptionUnavailableIconFilename, releaseDescriptionSeparatorIconFilename, "artifacts.md", "release-notes.md", "release.json", releaseManifestFilename} {
		require.FileExists(t, filepath.Join(options.output, name))
	}
	for filename, expected := range map[string][]byte{
		releaseDescriptionDownloadIconFilename:    releaseDescriptionDownloadIcon,
		releaseDescriptionUnavailableIconFilename: releaseDescriptionUnavailableIcon,
		releaseDescriptionSeparatorIconFilename:   releaseDescriptionSeparatorIcon,
	} {
		actual, err := os.ReadFile(filepath.Join(options.output, filename))
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
	body, err := os.ReadFile(filepath.Join(options.output, "release-notes.md"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(body), "Manual notes\n\n"))
	require.True(t, strings.HasSuffix(string(body), "\n\nMore notes"))
}

func TestReleaseDescriptionUpdateReReadsManualNotesAndOnlyPatchesBody(t *testing.T) {
	api := &releaseDescriptionTestAPI{source: testReleaseDescriptionSource(), currentBody: "New manual notes\n" + releaseArtifactsPlaceholder + "\nKeep this footer"}
	client := newDependencyTestGitHubClient(t, api.serve)
	repository := newDependencyTestRepo(client)
	repository.githubToken = "test-token"
	options := &releaseDescriptionOptions{repository: repository, tag: "v1.2.3-beta1"}
	require.NoError(t, options.run(t.Context(), true))
	api.Lock()
	require.Len(t, api.patches, 1)
	require.Len(t, api.patches[0], 1)
	body := api.source.Release.GetBody()
	require.True(t, strings.HasPrefix(body, "New manual notes\n"))
	require.True(t, strings.HasSuffix(body, "\nKeep this footer"))
	require.NotContains(t, body, "Manual notes\n\n")
	api.Unlock()
	require.NoError(t, options.run(t.Context(), true))
	api.Lock()
	defer api.Unlock()
	require.Len(t, api.patches, 1, "unchanged descriptions must not cause another PATCH")
}

func TestReleaseDescriptionUpdateFailsWithoutWritingForInvalidCurrentBodyOrStatus(t *testing.T) {
	for _, statusChanged := range []bool{false, true} {
		t.Run(strconv.FormatBool(statusChanged), func(t *testing.T) {
			api := &releaseDescriptionTestAPI{source: testReleaseDescriptionSource(), currentBody: releaseArtifactsBegin, currentBroken: statusChanged}
			repository := newDependencyTestRepo(newDependencyTestGitHubClient(t, api.serve))
			repository.githubToken = "test-token"
			options := &releaseDescriptionOptions{repository: repository, tag: "v1.2.3-beta1"}
			require.Error(t, options.run(t.Context(), true))
			api.Lock()
			defer api.Unlock()
			require.Empty(t, api.patches)
		})
	}
}

func TestReleaseDescriptionSnapshotAndCLIWorkWithoutCredentialsOrNetwork(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	source := testReleaseDescriptionSource()
	view, err := newReleaseDescriptionView(source)
	require.NoError(t, err)
	snapshot := t.TempDir()
	require.NoError(t, writeReleaseDescriptionPreview(snapshot, source, view, renderReleaseDescription(view), "body"))
	bodyFile := filepath.Join(t.TempDir(), "description.md")
	require.NoError(t, os.WriteFile(bodyFile, []byte("My own notes\n"+releaseArtifactsPlaceholder), 0644))
	output := t.TempDir()
	app := kingpin.New("build", "test")
	repository := newRepo(&base{})
	initReleaseDescription(context.Background(), app, repository)
	_, err = app.Parse([]string{"release-description", "--owner", "owner", "--repo", "repository", "preview", "v1.2.3-beta1", "--snapshot", snapshot, "--body-file", bodyFile, "--output", output})
	require.NoError(t, err)
	body, err := os.ReadFile(filepath.Join(output, "release-notes.md"))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(body), "My own notes\n"))
	loaded, err := readReleaseDescriptionSnapshot(output)
	require.NoError(t, err)
	require.NoError(t, validateReleaseDescriptionSource(loaded, "owner/repository", source.Manifest.Version))
	require.Nil(t, repository.clientP.Load(), "offline previews must never initialize the GitHub client")
	_, err = readReleaseDescriptionInput(strings.NewReader(strings.Repeat("x", releaseDescriptionMaxInput+1)))
	require.ErrorContains(t, err, "exceeds")
	options := &releaseDescriptionOptions{repository: repository, tag: source.Manifest.Version}
	require.ErrorContains(t, options.run(t.Context(), true), "require GITHUB_TOKEN")
}
