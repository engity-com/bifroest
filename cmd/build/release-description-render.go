package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-github/v65/github"

	"github.com/engity-com/bifroest/pkg/sys"
)

//go:embed release-description-table.gohtml
var releaseDescriptionTableTemplate string

//go:embed release-description-preview.gohtml
var releaseDescriptionPreviewTemplate string

//go:embed release-description-download.svg
var releaseDescriptionDownloadIcon []byte

//go:embed release-description-unavailable.svg
var releaseDescriptionUnavailableIcon []byte

//go:embed release-description-separator.svg
var releaseDescriptionSeparatorIcon []byte

const (
	releaseDescriptionDownloadIconFilename    = "release-description-download.svg"
	releaseDescriptionUnavailableIconFilename = "release-description-unavailable.svg"
	releaseDescriptionSeparatorIconFilename   = "release-description-separator.svg"
	releaseDescriptionIconBaseURL             = "https://raw.githubusercontent.com/engity-com/bifroest/main/cmd/build/"
	releaseDescriptionDownloadIconURL         = releaseDescriptionIconBaseURL + releaseDescriptionDownloadIconFilename
	releaseDescriptionUnavailableIconURL      = releaseDescriptionIconBaseURL + releaseDescriptionUnavailableIconFilename
	releaseDescriptionSeparatorIconURL        = releaseDescriptionIconBaseURL + releaseDescriptionSeparatorIconFilename
)

var releaseDescriptionDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type releaseDescriptionSource struct {
	Release  *github.RepositoryRelease
	Manifest releaseManifest
}

type releaseDescriptionLink struct {
	URL   string
	Title string
}

type releaseDescriptionCell struct {
	Links []releaseDescriptionLink
}

type releaseDescriptionRow struct {
	Architecture string
	Cells        []releaseDescriptionCell
}

type releaseDescriptionTable struct {
	OperatingSystems   []string
	Columns            []string
	Rows               []releaseDescriptionRow
	DownloadIconURL    string
	UnavailableIconURL string
	SeparatorIconURL   string
}

type releaseDescriptionView struct {
	Tag          string
	DocsURL      string
	ChecksumsURL string
	ManifestURL  string
	ArchiveTable template.HTML
	ImageTable   template.HTML
	PullCommands []string
	ChartURL     string
	ChartCommand string
	ChartDocsURL string
}

func releaseDescriptionAssetName(name string) bool {
	return name != "" && name != "." && path.Base(name) == name && !strings.ContainsAny(name, "\\\r\n")
}

func validateReleaseDescriptionSource(source releaseDescriptionSource, repository, tag string) error {
	if !releaseVersionPattern.MatchString(tag) {
		return fmt.Errorf("invalid release tag %q", tag)
	}
	manifest := source.Manifest
	if manifest.SchemaVersion != 1 && manifest.SchemaVersion != 2 {
		return fmt.Errorf("unsupported release manifest schema %d", manifest.SchemaVersion)
	}
	if manifest.Project != repository || manifest.Version != tag || source.Release == nil || source.Release.GetTagName() != tag {
		return fmt.Errorf("release and manifest must belong to %s at %s", repository, tag)
	}
	if source.Release.GetDraft() || source.Release.GetPrerelease() != strings.Contains(tag, "-") {
		return fmt.Errorf("release %s has incorrect draft or prerelease status", tag)
	}
	if manifest.Registry != "ghcr.io/"+repository {
		return fmt.Errorf("release manifest registry does not match %s", repository)
	}
	if manifest.ManifestAsset != releaseManifestFilename || !releaseDescriptionAssetName(manifest.ChecksumAsset) || manifest.ChecksumAsset == manifest.ManifestAsset {
		return fmt.Errorf("release manifest has invalid manifest or checksum asset")
	}
	published := make(map[string]bool)
	for _, asset := range source.Release.Assets {
		if !releaseDescriptionAssetName(asset.GetName()) || published[asset.GetName()] {
			return fmt.Errorf("invalid or duplicate published asset %q", asset.GetName())
		}
		published[asset.GetName()] = true
	}
	inventory := map[string]bool{manifest.ManifestAsset: true, manifest.ChecksumAsset: true}
	for _, asset := range manifest.Assets {
		if !releaseDescriptionAssetName(asset.Name) || inventory[asset.Name] || !releaseDescriptionDigestPattern.MatchString(asset.Digest) {
			return fmt.Errorf("invalid or duplicate manifest asset %q", asset.Name)
		}
		inventory[asset.Name] = true
	}
	for name := range inventory {
		if !published[name] {
			return fmt.Errorf("release is missing asset %q", name)
		}
	}
	for name := range published {
		if !inventory[name] {
			return fmt.Errorf("release has unexpected asset %q", name)
		}
	}
	requireAsset := func(name string) error {
		if !inventory[name] || name == manifest.ManifestAsset || name == manifest.ChecksumAsset {
			return fmt.Errorf("release variant references unknown artifact %q", name)
		}
		return nil
	}
	seen := make(map[string]bool)
	if len(manifest.Variants) == 0 {
		return fmt.Errorf("release manifest has no variants")
	}
	for _, variant := range manifest.Variants {
		var targetOs sys.Os
		var architecture sys.Arch
		if err := targetOs.Set(variant.Os); err != nil {
			return err
		}
		if err := architecture.Set(variant.Architecture); err != nil {
			return err
		}
		if variant.Edition != "generic" && variant.Edition != "extended" {
			return fmt.Errorf("unsupported release edition %q", variant.Edition)
		}
		key := variant.Os + "/" + variant.Architecture + "/" + variant.Edition
		if seen[key] {
			return fmt.Errorf("duplicate release variant %s", key)
		}
		seen[key] = true
		if err := requireAsset(variant.Archive); err != nil {
			return err
		}
		for _, sboms := range []*releaseManifestSbomFiles{variant.Sboms.Archive, variant.Sboms.Image} {
			if sboms == nil {
				continue
			}
			for _, name := range []string{sboms.Spdx, sboms.CycloneDx} {
				if err := requireAsset(name); err != nil {
					return err
				}
			}
		}
		if variant.Sboms.Archive == nil || (variant.Image == nil) != (variant.Sboms.Image == nil) {
			return fmt.Errorf("release variant %s has incomplete SBOMs", key)
		}
	}
	if chart := manifest.Chart; chart != nil {
		if chart.Version != strings.TrimPrefix(tag, "v") {
			return fmt.Errorf("chart version does not match release %s", tag)
		}
		if err := requireAsset(chart.Asset); err != nil {
			return err
		}
	}
	return nil
}

func releaseDescriptionOSName(targetOs string) string {
	switch targetOs {
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return targetOs
	}
}

func newReleaseDescriptionView(source releaseDescriptionSource) (releaseDescriptionView, error) {
	manifest := source.Manifest
	view := releaseDescriptionView{
		Tag:     manifest.Version,
		DocsURL: "https://bifroest.engity.org/" + url.PathEscape(manifest.Version) + "/setup/",
	}
	assetURL := func(name string) string {
		return "https://github.com/" + manifest.Project + "/releases/download/" + url.PathEscape(manifest.Version) + "/" + url.PathEscape(name)
	}
	view.ChecksumsURL = assetURL(manifest.ChecksumAsset)
	view.ManifestURL = assetURL(manifest.ManifestAsset)
	variants := make(map[string]releaseManifestVariant)
	architectures := make(map[sys.Arch]bool)
	imageEditions := make(map[string]bool)
	for _, variant := range manifest.Variants {
		variants[variant.Os+"/"+variant.Architecture+"/"+variant.Edition] = variant
		var arch sys.Arch
		if err := arch.Set(variant.Architecture); err != nil {
			return view, err
		}
		architectures[arch] = true
		if variant.Image != nil {
			imageEditions[variant.Edition] = true
		}
	}
	arches := make([]sys.Arch, 0, len(architectures))
	for arch := range architectures {
		arches = append(arches, arch)
	}
	slices.Sort(arches)
	tableTemplate, err := template.New("table").Parse(releaseDescriptionTableTemplate)
	if err != nil {
		return view, err
	}
	for _, subject := range []string{"archive", "image"} {
		table := releaseDescriptionTable{
			OperatingSystems:   []string{"Linux", "macOS", "Windows"},
			Columns:            []string{"SPDX", "CycloneDX"},
			DownloadIconURL:    releaseDescriptionDownloadIconURL,
			UnavailableIconURL: releaseDescriptionUnavailableIconURL,
			SeparatorIconURL:   releaseDescriptionSeparatorIconURL,
		}
		if subject == "archive" {
			table.Columns = append([]string{"Download"}, table.Columns...)
		}
		for _, arch := range arches {
			row := releaseDescriptionRow{Architecture: arch.String()}
			for _, targetOs := range []string{"linux", "darwin", "windows"} {
				for _, column := range table.Columns {
					cell := releaseDescriptionCell{}
					for _, edition := range []string{"generic", "extended"} {
						variant := variants[targetOs+"/"+arch.String()+"/"+edition]
						name := ""
						sboms := variant.Sboms.Archive
						if subject == "image" {
							sboms = variant.Sboms.Image
						}
						switch {
						case column == "Download":
							name = variant.Archive
						case column == "SPDX" && sboms != nil:
							name = sboms.Spdx
						case column == "CycloneDX" && sboms != nil:
							name = sboms.CycloneDx
						}
						link := releaseDescriptionLink{Title: releaseDescriptionOSName(targetOs) + " / " + arch.String() + " / " + edition + " / " + subject + " / " + column}
						if name != "" {
							link.URL = assetURL(name)
						} else {
							link.Title += " is not available"
						}
						cell.Links = append(cell.Links, link)
					}
					row.Cells = append(row.Cells, cell)
				}
			}
			table.Rows = append(table.Rows, row)
		}
		var output bytes.Buffer
		if err := tableTemplate.Execute(&output, table); err != nil {
			return view, err
		}
		// Only HTML produced by html/template is trusted, never release body text.
		if subject == "archive" {
			view.ArchiveTable = template.HTML(output.String())
		} else if len(imageEditions) > 0 {
			view.ImageTable = template.HTML(output.String())
		}
	}
	for _, edition := range []string{"generic", "extended"} {
		if imageEditions[edition] {
			view.PullCommands = append(view.PullCommands,
				"docker pull "+manifest.Registry+":"+edition+"-"+strings.TrimPrefix(manifest.Version, "v"))
		}
	}
	if chart := manifest.Chart; chart != nil {
		view.ChartURL = assetURL(chart.Asset)
		view.ChartCommand = "helm pull oci://" + manifest.Registry + " --version " + chart.Version
		view.ChartDocsURL = view.DocsURL + "in-kubernetes/"
	}
	return view, nil
}

func renderReleaseDescription(view releaseDescriptionView) string {
	var output strings.Builder
	fmt.Fprintf(&output, "## Downloads\n\n[Installation and platform details](%sdistribution/) · [SHA-256 checksums](%s) · [Release manifest](%s)\n\n", view.DocsURL, view.ChecksumsURL, view.ManifestURL)
	fmt.Fprintf(&output, "Each entry shows **Generic / Extended**. <img src=\"%s\" width=\"16\" height=\"16\" align=\"middle\" alt=\"○\"> means not available.\n\n", releaseDescriptionUnavailableIconURL)
	output.WriteString(string(view.ArchiveTable))
	if len(view.PullCommands) > 0 {
		fmt.Fprintf(&output, "\n\n## Docker/OCI images\n\n[Container installation instructions](%sin-docker/)\n\n", view.DocsURL)
		for _, command := range view.PullCommands {
			fmt.Fprintf(&output, "```sh\n%s\n```\n\n", command)
		}
		output.WriteString(string(view.ImageTable))
	}
	if view.ChartURL != "" {
		fmt.Fprintf(&output, "\n\n## Helm chart\n\n[Download the chart](%s) · [Installation instructions](%s)\n\n```sh\n%s\n```\n", view.ChartURL, view.ChartDocsURL, view.ChartCommand)
	}
	return strings.TrimSpace(output.String()) + "\n"
}

func renderReleaseDescriptionPreview(writer io.Writer, view releaseDescriptionView) error {
	// Only the local HTML uses adjacent files; GitHub Markdown keeps the HTTPS image URLs.
	icons := strings.NewReplacer(
		releaseDescriptionDownloadIconURL, releaseDescriptionDownloadIconFilename,
		releaseDescriptionUnavailableIconURL, releaseDescriptionUnavailableIconFilename,
		releaseDescriptionSeparatorIconURL, releaseDescriptionSeparatorIconFilename,
	)
	view.ArchiveTable = template.HTML(icons.Replace(string(view.ArchiveTable)))
	view.ImageTable = template.HTML(icons.Replace(string(view.ImageTable)))
	parsed, err := template.New("preview").Parse(releaseDescriptionPreviewTemplate)
	if err != nil {
		return err
	}
	return parsed.Execute(writer, view)
}

func decodeReleaseDescriptionManifest(raw []byte) (releaseManifest, error) {
	var manifest releaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("cannot decode release manifest: %w", err)
	}
	return manifest, nil
}
